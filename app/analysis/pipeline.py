"""
Main ScamRead analysis pipeline.

extract indicators -> score with rules -> match known campaigns -> build response.

Speed-ups compared with v1:
- patterns are compiled once and reloaded every few minutes, not rebuilt per check;
- a repeated message is answered from a short-lived in-memory cache;
- campaign matching skips the database when no indicator is known;
- anonymous pattern statistics are queued and written in the background.
"""

import json

from app.analysis import campaign_matcher, extractor, response_builder, rule_engine
from app.analysis import patterns as pattern_store
from app.analysis.cache import ResultCache, results
from app.services import observations


def _analyze_uncached(text: str, patterns) -> dict:
    extraction = extractor.run(text)
    indicators = extraction["indicators"]
    analysis = rule_engine.analyze(text, indicators, patterns)
    campaign = campaign_matcher.match(indicators)
    observations.record(
        observations.build_observation(analysis, indicators.domains, patterns.all_legit_domains)
    )
    return response_builder.build(extraction, analysis, campaign)


def analyze(text: str) -> dict:
    """Return the full analysis as a dict (used by tests and internal callers)."""
    return json.loads(analyze_json(text))


def analyze_json(text: str, cache: ResultCache = results) -> bytes:
    """Return the full analysis as ready-to-send JSON bytes, using the cache when possible."""
    patterns = pattern_store.current()
    key = cache.key(text, patterns.version)
    cached = cache.get(key)
    if cached is not None:
        return cached
    body = json.dumps(
        _analyze_uncached(text, patterns),
        default=lambda value: value.model_dump(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    cache.set(key, body)
    return body
