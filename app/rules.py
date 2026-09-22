from typing import Dict, Any, List

CWE_DATABASE: Dict[str, Dict[str, Any]] = {
    "CWE-120": {
        "name": "Classic Buffer Overflow",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Копіювання даних у буфер фіксованого розміру без перевірки довжини. Може призвести до перезапису стека та RCE."
    },
    "CWE-242": {
        "name": "Use of Inherently Dangerous Function",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Використання функції gets(), яку неможливо викликати безпечно. Заборонена стандартом C11."
    },
    "CWE-134": {
        "name": "Uncontrolled Format String",
        "severity": "HIGH",
        "cvss": 8.6,
        "description": "Передача рядка користувача безпосередньо у printf(). Дозволяє вичитувати або перезаписувати пам'ять через %n."
    },
    "CWE-416": {
        "name": "Use After Free (UAF)",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "description": "Звернення до вказівника після виклику free(). Дозволяє зловмиснику виконати код через повторне виділення об'єкта."
    },
    "CWE-415": {
        "name": "Double Free",
        "severity": "HIGH",
        "cvss": 7.8,
        "description": "Повторне звільнення пам'яті за тим самим вказівником. Призводить до пошкодження купи (Heap Corruption)."
    },
    "CWE-190": {
        "name": "Integer Overflow in Allocation",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Множення розмірів всередині malloc() без перевірки на переповнення. Виділяється замалий буфер, що веде до Heap Overflow."
    },
    "CWE-467": {
        "name": "Use of sizeof() on a Pointer Type",
        "severity": "HIGH",
        "cvss": 7.2,
        "description": "Виклик sizeof(ptr) замість розміру масиву. Повертає розмір самого вказівника (8 байт), а не даних."
    },
    "CWE-770": {
        "name": "Stack Exhaustion via alloca()",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Виділення динамічної пам'яті на стеку через alloca(). Спричиняє миттєвий краш програми при великих розмірах."
    },
    "CWE-377": {
        "name": "Insecure Temporary File (TOCTOU)",
        "severity": "MEDIUM",
        "cvss": 6.3,
        "description": "Використання mktemp()/tmpnam() для тимчасових файлів. Вразливе до створення симлінків зловмисником."
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Виклик системної оболонки через system() або popen(). Дозволяє виконання довільних команд ОС."
    }
}

DANGEROUS_PATTERNS = [
    # 1. BANNED STRINGS
    {
        "pattern": r"\b(?:strcpy|wcscpy|_tcscpy|_mbscpy)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-120",
        "fix": "strncpy({dst}, {src}, sizeof({dst}) - 1); {dst}[sizeof({dst}) - 1] = '\\0';"
    },
    {
        "pattern": r"\b(?:strcat|wcscat|_tcscat|_mbscat)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-120",
        "fix": "strncat({dst}, {src}, sizeof({dst}) - strlen({dst}) - 1);"
    },
    {
        "pattern": r"\b(?:stpcpy|wcpcpy)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-120",
        "fix": "snprintf({dst}, sizeof({dst}), \"%s\", {src});"
    },

    # 2. FORMAT STRINGS
    {
        "pattern": r"\b(?:sprintf|wsprintf|vsprintf)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-120",
        "fix": "snprintf({dst}, sizeof({dst}), \"%s\", {src});"
    },
    {
        "pattern": r"\b(?:printf|vprintf)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-134",
        "fix": "printf(\"%s\", {dst});"
    },
    {
        "pattern": r"\bfprintf\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-134",
        "fix": "fprintf({dst}, \"%s\", {src});"
    },

    # 3. INPUTS
    {
        "pattern": r"\b(?:gets|_getts|_getws)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-242",
        "fix": "fgets({dst}, sizeof({dst}), stdin);"
    },
    {
        "pattern": r"\bscanf\s*\(\s*\"%s\"\s*,\s*([a-zA-Z0-9_&>.-]+)\s*\)",
        "cwe": "CWE-120",
        "fix": "scanf(\"%127s\", {dst}); // Додайте ліміт ширини"
    },

    # 4. MEMORY & STACK
    {
        "pattern": r"\b(?:alloca|_alloca)\s*\(\s*([a-zA-Z0-9_>.*+-/ ]+)\s*\)",
        "cwe": "CWE-770",
        "fix": "malloc({dst}); // Використовуйте купу замість стека"
    },
    {
        "pattern": r"\bmalloc\s*\(\s*([a-zA-Z0-9_]+)\s*\*\s*sizeof\s*\(",
        "cwe": "CWE-190",
        "fix": "calloc({dst}, sizeof(...)); // calloc захищає від переповнення"
    },
    {
        "pattern": r"\b(?:memcpy|memmove|memset|strncpy)\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\)",
        "cwe": "CWE-467",
        "fix": "// Використовуйте реальний розмір буфера, а не sizeof({dst})"
    },

    # 5. DANGEROUS SYSTEM CALLS
    {
        "pattern": r"\b(?:mktemp|tmpnam|tempnam)\s*\(",
        "cwe": "CWE-377",
        "fix": "mkstemp(template); // Використовуйте безпечне атомарне створення файлу"
    },
    {
        "pattern": r"\b(?:system|popen)\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "cwe": "CWE-78",
        "fix": "execve(path, argv, envp); // Уникайте передачі рядків у командну оболонку"
    }
]