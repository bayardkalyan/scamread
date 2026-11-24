"""
Wrapper around the IOC regex extractor.

This module exists so the rest of the application does not
depend directly on regex.py.
"""

from app.extractors.regex import extract_indicators, count_indicators


def run(text: str) -> dict:
    """
    Run IOC extraction.

    Returns:
        {
            "indicators": Indicators,
            "total_indicators": int
        }
    """

    indicators = extract_indicators(text)

    return {
        "indicators": indicators,
        "total_indicators": count_indicators(indicators),
    }