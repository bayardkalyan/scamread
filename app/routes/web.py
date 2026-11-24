"""Routes that render ScamRead web pages."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


# Templates are kept outside the Python package so designers can find them easily.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))

router = APIRouter()


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request) -> HTMLResponse:
    """Render the public analyzer page without storing any user-submitted text."""
    return templates.TemplateResponse(request=request, name="index.html")

