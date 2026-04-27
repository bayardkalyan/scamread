from app.schemas import ScamAnalysis


def fallback_analysis(
    explanation: str,
    recommended_action: str = "Try again later. If the message seems suspicious, do not click links or share personal information.",
    risk_level: str = "medium",
    risk_score: int = 50,
) -> ScamAnalysis:
    return ScamAnalysis(
        risk_score=risk_score,
        risk_level=risk_level,
        scam_type="analysis_unavailable",
        red_flags=["Automated scam analysis could not be completed."],
        explanation=explanation,
        recommended_action=recommended_action,
    )

