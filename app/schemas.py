from typing import Literal
from pydantic import BaseModel, Field


RiskLevel = Literal["low", "medium", "high", "critical"]


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000)


class ScamAnalysis(BaseModel):
    risk_score: int = Field(..., description="Integer from 0 to 100.")
    risk_level: RiskLevel
    scam_type: str
    red_flags: list[str]
    explanation: str
    recommended_action: str
