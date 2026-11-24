"""Models for storing analyst-reviewed scam-intelligence observations."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.ioc import AnalyzeRequest, ExtractionResponse


ReviewStatus = Literal["unreviewed", "reviewed", "published", "rejected"]


class IntelligenceCaptureRequest(AnalyzeRequest):
    """Combine text with optional labels a curator can revise later in Excel."""

    category: str = Field(default="Uncategorized", max_length=80)
    cluster: str = Field(default="Unclustered", max_length=120)
    impersonated_brand: str | None = Field(default=None, max_length=120)
    platform: str | None = Field(default=None, max_length=80)
    countries: list[str] = Field(default_factory=list, max_length=20)
    source_reference: str | None = Field(default=None, max_length=500)
    analyst_notes: str | None = Field(default=None, max_length=2_000)
    review_status: ReviewStatus = "unreviewed"


class IntelligenceCaptureResponse(ExtractionResponse):
    """Confirm that an immutable raw observation was stored for later review."""

    observation_id: int
    captured_at: datetime


class KnownIndicator(BaseModel):
    """Describe one indicator that links pasted text to a known campaign."""

    indicator_type: str
    indicator_value: str


class CampaignSummary(BaseModel):
    """Expose only reviewed campaign information suitable for a public response."""

    campaign_id: str
    title: str
    status: str
    first_seen: str | None = None
    last_seen: str | None = None
    countries: list[str] = Field(default_factory=list)
    impersonated_brand: str | None = None
    threat_type: str | None = None
    cluster: str | None = None
    summary: str | None = None


class CampaignMatch(BaseModel):
    """Pair a published campaign with the indicators that matched it exactly."""

    campaign: CampaignSummary
    matched_indicators: list[KnownIndicator]


class CampaignLookupResponse(ExtractionResponse):
    """Return extracted indicators and any exact matches in the campaign database."""

    matches: list[CampaignMatch]
