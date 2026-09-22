import re
from typing import List, Dict, Any
from app.rules import CWE_DATABASE, DANGEROUS_PATTERNS

class MemoryVulnerabilityScanner:
    def scan_code(self, source_code: str) -> Dict[str, Any]:
        lines = source_code.splitlines()
        findings: List[Dict[str, Any]] = []
        pointer_tracker: Dict[str, Dict[str, Any]] = {}

        alloc_pattern = re.compile(r"\b([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_* ]+\)\s*)?(?:malloc|calloc|realloc)\s*\(")
        free_pattern = re.compile(r"\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)")
        null_reset_pattern = re.compile(r"\b([a-zA-Z0-9_]+)\s*=\s*(?:NULL|0)\s*;")

        for idx, line in enumerate(lines, start=1):
            clean_line = line.strip()

            if not clean_line or clean_line.startswith("//") or clean_line.startswith("/*"):
                continue

            # 1. Пошук за патернами DANGEROUS_PATTERNS
            for rule in DANGEROUS_PATTERNS:
                match = re.search(rule["pattern"], clean_line)
                if match:
                    cwe_info = CWE_DATABASE[rule["cwe"]]
                    groups = match.groups()

                    dst_val = groups[0] if len(groups) > 0 else "target"
                    src_val = groups[1] if len(groups) > 1 else "source"

                    try:
                        remediation = rule["fix"].format(dst=dst_val, src=src_val)
                    except Exception:
                        remediation = rule["fix"]

                    findings.append({
                        "id": f"VULN-{len(findings) + 1}",
                        "line": idx,
                        "cwe": rule["cwe"],
                        "name": cwe_info["name"],
                        "severity": cwe_info["severity"],
                        "cvss": cwe_info["cvss"],
                        "vulnerable_code": clean_line,
                        "remediation": remediation,
                        "description": cwe_info["description"]
                    })

            # 2. Відстеження malloc
            alloc_match = alloc_pattern.search(clean_line)
            if alloc_match:
                ptr_name = alloc_match.group(1)
                pointer_tracker[ptr_name] = {"state": "ALLOCATED", "line": idx}

            # 3. Відстеження ptr = NULL
            null_match = null_reset_pattern.search(clean_line)
            if null_match:
                ptr_name = null_match.group(1)
                if ptr_name in pointer_tracker:
                    pointer_tracker[ptr_name] = {"state": "NULLIFIED", "line": idx}

            # 4. Відстеження free() -> Double Free
            free_match = free_pattern.search(clean_line)
            if free_match:
                ptr_name = free_match.group(1)
                if ptr_name in pointer_tracker and pointer_tracker[ptr_name]["state"] == "FREED":
                    prev_line = pointer_tracker[ptr_name]["line"]
                    cwe_info = CWE_DATABASE["CWE-415"]
                    findings.append({
                        "id": f"VULN-{len(findings) + 1}",
                        "line": idx,
                        "cwe": "CWE-415",
                        "name": cwe_info["name"],
                        "severity": cwe_info["severity"],
                        "cvss": cwe_info["cvss"],
                        "vulnerable_code": clean_line,
                        "remediation": f"// Встановіть {ptr_name} = NULL після першого free() на рядку {prev_line} або видаліть повторний виклик.",
                        "description": f"Вказівник '{ptr_name}' уже був звільнений на рядку {prev_line}."
                    })
                else:
                    pointer_tracker[ptr_name] = {"state": "FREED", "line": idx}

            # 5. Відстеження Use-After-Free (UAF)
            for ptr_name, meta in list(pointer_tracker.items()):
                if meta["state"] == "FREED" and idx > meta["line"]:
                    uaf_usage = re.search(rf"\b{ptr_name}\s*(?:->|\[|\.|\*|\=)", clean_line) or re.search(rf"\*\s*{ptr_name}\b", clean_line)
                    if uaf_usage and not free_pattern.search(clean_line) and not null_reset_pattern.search(clean_line):
                        cwe_info = CWE_DATABASE["CWE-416"]
                        findings.append({
                            "id": f"VULN-{len(findings) + 1}",
                            "line": idx,
                            "cwe": "CWE-416",
                            "name": cwe_info["name"],
                            "severity": cwe_info["severity"],
                            "cvss": cwe_info["cvss"],
                            "vulnerable_code": clean_line,
                            "remediation": f"// Уникайте звернення до '{ptr_name}' після звільнення на рядку {meta['line']}.",
                            "description": f"Спроба доступу до звільненої пам'яті через '{ptr_name}'."
                        })

        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

        risk_score = round(min(critical_count * 30.0 + high_count * 15.0 + medium_count * 5.0, 100.0), 1)

        return {
            "total_lines": len(lines),
            "findings_count": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "risk_score": risk_score,
            "findings": findings
        }