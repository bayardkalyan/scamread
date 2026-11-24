"""Campaign matching logic."""

from app.services.campaign_store import find_campaign_matches


def match(indicators):
    matches = find_campaign_matches(indicators)

    if not matches:
        return {
            "matched": False,
            "campaign": None,
            "confidence": 0,
        }

    best_match = matches[0]

    return {
        "matched": True,
        "campaign": best_match.model_dump(),
        "confidence": 100,
    }