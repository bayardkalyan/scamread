"""Routes that render ScamRead web pages.

The page has no per-visitor content, so it is rendered once and served from
memory.
"""

from functools import lru_cache

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, PlainTextResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app import config

templates = Environment(
    loader=FileSystemLoader(str(config.PROJECT_ROOT / "templates")),
    autoescape=select_autoescape(["html"]),
)

router = APIRouter()


def static_url(path: str) -> str:
    """Versioned static URL, so browsers can cache files for a year safely."""
    return f"/static/{path}?v={config.ASSET_VERSION}"


@lru_cache(maxsize=8)
def render(name: str) -> bytes:
    return templates.get_template(name).render(static=static_url).encode("utf-8")


@router.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse, include_in_schema=False)
def home() -> HTMLResponse:
    """The public checker page. Nothing the visitor types is stored."""
    return HTMLResponse(render("index.html"), headers={"Cache-Control": "public, max-age=300"})


@router.get("/robots.txt", include_in_schema=False)
def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nAllow: /\nDisallow: /api/\n")
