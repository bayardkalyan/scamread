"""Read reviewed scam campaigns and match extracted indicators against them."""

import json
import sqlite3
from collections import defaultdict

from app.models.intelligence import CampaignMatch, CampaignSummary, KnownIndicator
from app.models.ioc import Indicators
from app.services.intelligence_store import get_connection, initialize_database


# These names are stable database values, independent from Python model field names.
INDICATOR_TYPES = {
    "urls": "url",
    "domains": "domain",
    "email_addresses": "email_address",
    "phone_numbers": "phone_number",
    "ipv4_addresses": "ipv4_address",
    "md5_hashes": "md5",
    "sha1_hashes": "sha1",
    "sha256_hashes": "sha256",
    "bitcoin_wallets": "bitcoin_wallet",
    "ethereum_wallets": "ethereum_wallet",
}


def campaign_from_row(row: sqlite3.Row) -> CampaignSummary:
    """Convert one database row into a typed API response without exposing raw reports."""
    return CampaignSummary(
        campaign_id=row["campaign_id"],
        title=row["title"],
        status=row["status"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        countries=json.loads(row["countries_json"]),
        impersonated_brand=row["impersonated_brand"],
        threat_type=row["threat_type"],
        cluster=row["cluster"],
        summary=row["summary"],
    )

def create_campaign(
    campaign_id: str,
    title: str,
    status: str,
    countries: list[str],
    impersonated_brand: str | None,
    threat_type: str | None,
    cluster: str | None,
    summary: str | None,
    review_status: str = "unreviewed",
) -> None:
    """Create a new campaign in the campaign database."""

    connection = get_connection()

    try:
        initialize_database(connection)

        with connection:
            connection.execute(
                """
                INSERT INTO campaigns (
                    campaign_id,
                    title,
                    status,
                    countries_json,
                    impersonated_brand,
                    threat_type,
                    cluster,
                    summary,
                    review_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    title,
                    status,
                    json.dumps(countries),
                    impersonated_brand,
                    threat_type,
                    cluster,
                    summary,
                    review_status,
                ),
            )
    finally:
        connection.close()

def add_campaign_indicator(
    campaign_id: str,
    indicator_type: str,
    indicator_value: str,
    first_seen: str | None = None,
    last_seen: str | None = None,
    source_reference: str | None = None,
    confidence: int | None = None,
) -> None:
    """Attach one indicator to an existing campaign."""

    connection = get_connection()

    try:
        initialize_database(connection)

        with connection:
            connection.execute(
                """
                INSERT INTO campaign_indicators (
                    campaign_id,
                    indicator_type,
                    indicator_value,
                    first_seen,
                    last_seen,
                    source_reference,
                    confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    indicator_type,
                    indicator_value,
                    first_seen,
                    last_seen,
                    source_reference,
                    confidence,
                ),
            )
    finally:
        connection.close()

def get_published_campaign(campaign_id: str) -> CampaignSummary | None:
    """Return one published campaign by its stable ID, or no result if it is not public."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        initialize_database(connection)
        row = connection.execute(
            """
            SELECT * FROM campaigns
            WHERE campaign_id = ? AND review_status = 'published'
            """,
            (campaign_id,),
        ).fetchone()
    finally:
        connection.close()

    return campaign_from_row(row) if row else None


def find_campaign_matches(indicators: Indicators) -> list[CampaignMatch]:
    """Find exact IOC matches using indexed lookups, never fuzzy guesses or AI opinions."""
    matches: dict[str, list[KnownIndicator]] = defaultdict(list)
    campaign_rows: dict[str, sqlite3.Row] = {}
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        initialize_database(connection)
        for model_field, values in indicators.model_dump().items():
            indicator_type = INDICATOR_TYPES[model_field]
            for value in values:
                rows = connection.execute(
                    """
                    SELECT campaigns.*,
                           campaign_indicators.indicator_type,
                           campaign_indicators.indicator_value
                    FROM campaign_indicators
                    JOIN campaigns ON campaigns.campaign_id = campaign_indicators.campaign_id
                    WHERE campaign_indicators.indicator_type = ?
                      AND campaign_indicators.indicator_value = ?
                      AND campaigns.review_status = 'published'
                    """,
                    (indicator_type, value),
                ).fetchall()
                for row in rows:
                    campaign_id = row["campaign_id"]
                    campaign_rows[campaign_id] = row
                    matches[campaign_id].append(
                        KnownIndicator(
                            indicator_type=row["indicator_type"],
                            indicator_value=row["indicator_value"],
                        )
                    )
    finally:
        connection.close()

    return [
        CampaignMatch(
            campaign=campaign_from_row(campaign_rows[campaign_id]),
            matched_indicators=matched_indicators,
        )
        for campaign_id, matched_indicators in matches.items()
    ]
