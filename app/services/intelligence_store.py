"""Store extracted indicators as local, reviewable raw intelligence."""

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.models.intelligence import IntelligenceCaptureRequest
from app.models.ioc import Indicators


# SQLite is sufficient for local and single-instance hosting; deployers can mount this path persistently.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = Path(os.getenv("SCAMREAD_DATABASE_PATH", PROJECT_ROOT / "data" / "scamread.db"))


def utc_now() -> datetime:
    """Create timezone-aware timestamps so later reports can be compared reliably."""
    return datetime.now(UTC)


def get_connection() -> sqlite3.Connection:
    """Open a short-lived connection; FastAPI requests must not share SQLite connections."""
    DATABASE_PATH.parent.mkdir(exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create raw and reviewed intelligence tables plus their lookup indexes."""
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS raw_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT NOT NULL,
            text_fingerprint TEXT NOT NULL,
            category TEXT NOT NULL,
            cluster TEXT NOT NULL,
            impersonated_brand TEXT,
            platform TEXT,
            countries_json TEXT NOT NULL,
            source_reference TEXT,
            analyst_notes TEXT,
            review_status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS raw_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id INTEGER NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            FOREIGN KEY (observation_id) REFERENCES raw_observations(id)
        );

        CREATE INDEX IF NOT EXISTS idx_raw_indicators_value
            ON raw_indicators(indicator_value);

        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            countries_json TEXT NOT NULL,
            impersonated_brand TEXT,
            threat_type TEXT,
            cluster TEXT,
            summary TEXT,
            review_status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS campaign_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL COLLATE NOCASE,
            first_seen TEXT,
            last_seen TEXT,
            source_reference TEXT,
            confidence INTEGER,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
            UNIQUE (campaign_id, indicator_type, indicator_value)
        );

        CREATE INDEX IF NOT EXISTS idx_campaign_indicators_lookup
            ON campaign_indicators(indicator_type, indicator_value);
        CREATE INDEX IF NOT EXISTS idx_campaigns_public_status
            ON campaigns(review_status, status);
        """
    )


def fingerprint(text: str) -> str:
    """Link duplicate reports without keeping the original submitted message in the database."""
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
    try:
        initialize_database(connection)
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

            # One row per indicator preserves its type and makes future campaign matching fast.
            connection.executemany(
                """
                INSERT INTO raw_indicators (observation_id, indicator_type, indicator_value)
                VALUES (?, ?, ?)
                """,
                [(observation_id, indicator_type, indicator_value) for indicator_type, indicator_value in indicator_rows],
            )
    finally:
        # Context managers commit or roll back transactions but do not close SQLite connections.
        connection.close()

    return observation_id, captured_at
