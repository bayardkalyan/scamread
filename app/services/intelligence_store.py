"""Store analyst-captured indicators as reviewable raw intelligence (admin only)."""

import hashlib
import json
from datetime import UTC, datetime

from app.models.intelligence import IntelligenceCaptureRequest
from app.models.ioc import Indicators
from app.services.database import get_connection


def utc_now() -> datetime:
    """Create timezone-aware timestamps so later reports can be compared reliably."""
    return datetime.now(UTC)


def fingerprint(text: str) -> str:
    """Link duplicate analyst reports without keeping the original message in the database."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def capture_observation(
    payload: IntelligenceCaptureRequest,
    indicators: Indicators,
) -> tuple[int, datetime]:
    """Save metadata and every extracted indicator in one atomic database transaction."""
    captured_at = utc_now()
    indicator_rows = [
        (indicator_type, indicator_value)
        for indicator_type, values in indicators.model_dump().items()
        for indicator_value in values
    ]

    connection = get_connection()
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO raw_observations (
                captured_at, text_fingerprint, category, cluster, impersonated_brand,
                platform, countries_json, source_reference, analyst_notes, review_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                captured_at.isoformat(),
                fingerprint(payload.text),
                payload.category,
                payload.cluster,
                payload.impersonated_brand,
                payload.platform,
                json.dumps(payload.countries),
                payload.source_reference,
                payload.analyst_notes,
                payload.review_status,
            ),
        )
        observation_id = cursor.lastrowid
        connection.executemany(
            "INSERT INTO raw_indicators (observation_id, indicator_type, indicator_value) VALUES (?, ?, ?)",
            [(observation_id, t, v) for t, v in indicator_rows],
        )

    return observation_id, captured_at
