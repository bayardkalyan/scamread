"""
Main ScamRead analysis pipeline.

This module coordinates the different stages of analysis.
"""

from . import campaign_matcher
from . import extractor
from . import response_builder
from . import rule_engine


def analyze(text: str) -> dict:
    # Step 1: Extract technical indicators
    extraction = extractor.run(text)

    # Step 2: Analyze the message using our rule-based logic
    analysis = rule_engine.analyze(
        text,
        extraction["indicators"],
    )

    # Step 3: Check whether the indicators match a known campaign
    campaign = campaign_matcher.match(
        extraction["indicators"],
    )

    # Step 4: Combine everything into one response
    return response_builder.build(
        extraction,
        analysis,
        campaign,
    )