"""ScamRead application package and Uvicorn entry point."""

# Exposing the app here keeps the beginner-friendly command: uvicorn app:app --reload
from app.main import app
