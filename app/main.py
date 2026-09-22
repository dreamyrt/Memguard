import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.analyzer import MemoryVulnerabilityScanner

app = FastAPI(title=settings.PROJECT_NAME, version=settings.VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = MemoryVulnerabilityScanner()

class ScanRequest(BaseModel):
    code: str

CODE_PRESETS = {
    "BUFFER_OVERFLOW": """#include <stdio.h>
#include <string.h>

void auth_user(char *input) {
    char password[16];
    // ВРАЗЛИВІСТЬ: strcpy не перевіряє межі
    strcpy(password, input);
    printf("Auth: %s\\n", password);
}""",

    "USE_AFTER_FREE": """#include <stdio.h>
#include <stdlib.h>

struct Session {
    int auth_level;
    char token[32];
};

int main() {
    struct Session *sess = (struct Session*)malloc(sizeof(struct Session));
    free(sess);
    // ВРАЗЛИВІСТЬ: Use-After-Free
    sess->auth_level = 1;
    return 0;
}""",

    "DOUBLE_FREE": """#include <stdlib.h>

int main() {
    char *buf = (char*)malloc(128);
    free(buf);
    // Очищення іншої логіки...
    free(buf); // ВРАЗЛИВІСТЬ: Double Free
    return 0;
}""",

    "FORMAT_STRING": """#include <stdio.h>

void log_user(const char *user_input) {
    // ВРАЗЛИВІСТЬ: Небезпечний прямий друк
    printf(user_input);
}"""
}

@app.post("/api/v1/scan")
def scan_source_code(payload: ScanRequest):
    if not payload.code.strip():
        raise HTTPException(status_code=400, detail="Код для аналізу не може бути порожнім")
    return scanner.scan_code(payload.code)

@app.post("/api/v1/scan/file")
async def scan_file(file: UploadFile = File(...)):
    if not file.filename.endswith((".c", ".cpp", ".cc", ".h", ".hpp")):
        raise HTTPException(status_code=400, detail="Дозволені лише файли вихідного коду C/C++ (.c, .cpp, .h)")

    content = await file.read()
    code_text = content.decode("utf-8", errors="ignore")
    return scanner.scan_code(code_text)

@app.get("/api/v1/presets")
def get_presets():
    return CODE_PRESETS

# Створюємо папку static, якщо її немає
os.makedirs("static", exist_ok=True)
app.mount("/", StaticFiles(directory="static", html=True), name="static")