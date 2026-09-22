import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "MemGuard — Memory Safety SAST Analyzer"
    VERSION: str = "1.0.0"
    MAX_CODE_SIZE_KB: int = 512

settings = Settings()