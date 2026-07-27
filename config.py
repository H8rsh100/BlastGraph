"""Configuration management module loading settings via python-dotenv."""
import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()


class Config:
    """BlastGraph application configuration settings."""
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    CHROMA_DB_DIR: str = os.getenv("CHROMA_DB_DIR", "./chroma_db")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
