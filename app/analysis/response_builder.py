def build(
    extraction: dict,
    analysis: dict,
    campaign: dict,
) -> dict:

    return {
        "indicators": extraction["indicators"],
        "total_indicators": extraction["total_indicators"],
        "analysis": analysis,
        "campaign": campaign,
    }