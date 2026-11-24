"""Scam-intelligence routes.

Public: look up published campaigns (read-only).
Admin only: capture analyst-labelled observations.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.extractors.regex import count_indicators, extract_indicators
from app.models.intelligence import (
    CampaignLookupResponse,
    CampaignSummary,
    IntelligenceCaptureRequest,
    IntelligenceCaptureResponse,
)
from app.models.ioc import AnalyzeRequest
from app.security.admin import require_admin
from app.services.campaign_store import find_campaign_matches, get_published_campaign
from app.services.intelligence_store import capture_observation

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


@router.post(
    "/capture",
    response_model=IntelligenceCaptureResponse,
    status_code=201,
    dependencies=[Depends(require_admin)],
)
def capture_intelligence(payload: IntelligenceCaptureRequest) -> IntelligenceCaptureResponse:
    """Analyst only: save indicators and labels for review (the message text is not saved)."""
    indicators = extract_indicators(payload.text)
    observation_id, captured_at = capture_observation(payload, indicators)
    return IntelligenceCaptureResponse(
        observation_id=observation_id,
        captured_at=captured_at,
        indicators=indicators,
        total_indicators=count_indicators(indicators),
    )


@router.post("/lookup", response_model=CampaignLookupResponse)
def lookup_campaigns(payload: AnalyzeRequest) -> CampaignLookupResponse:
    """Extract indicators from text and return exact matches to published scam campaigns."""
    indicators = extract_indicators(payload.text)
    return CampaignLookupResponse(
        indicators=indicators,
        total_indicators=count_indicators(indicators),
        matches=find_campaign_matches(indicators),
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignSummary)
def get_campaign(campaign_id: str) -> CampaignSummary:
    """Return a published campaign without exposing unreviewed records."""
    campaign = get_published_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Published campaign not found.")
    return campaign
