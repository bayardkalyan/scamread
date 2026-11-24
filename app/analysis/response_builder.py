def build(
    extraction: dict,
    analysis: dict,
    campaign: dict,
) -> dict:
    """Combine all stages into the public response.

    The shape is unchanged from v1 (indicators, total_indicators, analysis,
    campaign); v2 only adds keys inside "analysis".
    """
    public_analysis = {k: v for k, v in analysis.items() if k != "red_flag_ids"}
    return {
        "indicators": extraction["indicators"],
        "total_indicators": extraction["total_indicators"],
        "analysis": public_analysis,
        "campaign": campaign,
    }
