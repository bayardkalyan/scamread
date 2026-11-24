"""Create and configure the FastAPI application."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes.api import router as api_router
from app.routes.intelligence import router as intelligence_router
from app.routes.web import router as web_router


# Resolve paths from this file so the app works from any current directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIRECTORY = PROJECT_ROOT / "static"

app = FastAPI(
    title="ScamRead",
    description="A deterministic scam-risk analyzer for suspicious messages and links.",
    version="0.1.0",
)

# Static files are mounted once so templates can load CSS and JavaScript reliably.
app.mount("/static", StaticFiles(directory=STATIC_DIRECTORY), name="static")

# Routes live separately so later API endpoints do not crowd application setup.
app.include_router(web_router)
app.include_router(api_router)
app.include_router(intelligence_router)
