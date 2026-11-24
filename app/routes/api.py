"""Public JSON API for the ScamRead checker."""

from fastapi import APIRouter, Response

from app.analysis import patterns as pattern_store
from app.analysis.pipeline import analyze_json
from app.models.ioc import AnalyzeRequest

APP_VERSION = "2.0.0"

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/analyze")
async def analyze_text(payload: AnalyzeRequest) -> Response:
    """Run the full analysis. The message is checked in memory and never saved."""
    return Response(
        content=analyze_json(payload.text),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/health")
async def health() -> dict:
    """Simple liveness check for monitoring."""
    return {
        "status": "ok",
        "version": APP_VERSION,
        "patterns_version": pattern_store.current().version,
    }
