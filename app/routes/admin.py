"""Admin endpoints for the pattern and campaign database (token required).

Everything here needs  Authorization: Bearer <SCAMREAD_ADMIN_TOKEN>.
If that setting is empty on the server, these endpoints answer 404.
"""

import json
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.analysis import patterns as pattern_store
from app.analysis.cache import results
from app.analysis.patterns import CATEGORIES
from app.security.admin import require_admin
from app.services import campaign_store, observations
from app.services.database import get_connection

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# ---------- statistics ----------


@router.get("/stats")
def stats(limit: int = 20) -> dict:
    """What the checker has seen: top brands, domain endings, scam domains and pattern shapes."""
    observations.flush()
    db = get_connection()
    limit = max(1, min(limit, 200))

    def rows(sql: str, *args) -> list[dict]:
        return [dict(r) for r in db.execute(sql, args).fetchall()]

    tld_counts: dict[str, int] = {}
    for r in db.execute("SELECT link_tlds_json, hits FROM pattern_observations"):
        for tld in json.loads(r["link_tlds_json"]):
            tld_counts[tld] = tld_counts.get(tld, 0) + r["hits"]

    return {
        "patterns_version": pattern_store.current().version,
        "cache": {"entries": len(results), "hits": results.hits, "misses": results.misses},
        "totals": rows(
            "SELECT COUNT(*) AS shapes, COALESCE(SUM(hits), 0) AS risky_checks FROM pattern_observations"
        )[0],
        "by_risk_level": rows(
            "SELECT risk_level, SUM(hits) AS hits FROM pattern_observations GROUP BY risk_level"
        ),
        "top_brands": rows(
            "SELECT claimed_brand, SUM(hits) AS hits, SUM(brand_mismatch * hits) AS with_fake_link "
            "FROM pattern_observations WHERE claimed_brand IS NOT NULL "
            "GROUP BY claimed_brand ORDER BY hits DESC LIMIT ?",
            limit,
        ),
        "top_link_endings": sorted(
            ({"tld": k, "hits": v} for k, v in tld_counts.items()), key=lambda x: -x["hits"]
        )[:limit],
        "top_scam_domains": rows(
            "SELECT domain, tld, claimed_brand, max_risk_score, first_seen, last_seen, hits "
            "FROM domain_observations ORDER BY hits DESC, last_seen DESC LIMIT ?",
            limit,
        ),
        "top_shapes": [
            {
                **r,
                "scam_types": json.loads(r.pop("scam_types_json")),
                "link_tlds": json.loads(r.pop("link_tlds_json")),
                "red_flags": json.loads(r.pop("red_flag_ids_json")),
            }
            for r in rows(
                "SELECT risk_level, scam_types_json, claimed_brand, brand_mismatch, link_tlds_json, "
                "urgency_score, red_flag_ids_json, first_seen, last_seen, hits "
                "FROM pattern_observations ORDER BY hits DESC LIMIT ?",
                limit,
            )
        ],
    }


# ---------- patterns ----------


class RuleIn(BaseModel):
    category: str = Field(description="One of: " + ", ".join(sorted(CATEGORIES)))
    value: str = Field(min_length=1, max_length=300)
    note: str | None = Field(default=None, max_length=300)


class BrandIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    legit_domains: list[str] = Field(min_length=1, max_length=30)
    sector: str | None = Field(default=None, max_length=40)


class TldIn(BaseModel):
    tld: str = Field(min_length=2, max_length=30)
    note: str | None = Field(default=None, max_length=300)


class ActiveIn(BaseModel):
    kind: Literal["rule", "brand", "tld"]
    key: str = Field(description="Rule id, brand name or TLD")
    active: bool


def _changed() -> dict:
    results.clear()
    return {"ok": True, "patterns_version": pattern_store.reload_now().version}


@router.get("/patterns")
def list_patterns() -> dict:
    db = get_connection()
    return {
        "rules": [dict(r) for r in db.execute("SELECT * FROM pattern_rules ORDER BY category, id")],
        "brands": [
            {**dict(r), "legit_domains": json.loads(r["legit_domains_json"])}
            for r in db.execute("SELECT * FROM brands ORDER BY position, name")
        ],
        "suspicious_tlds": [dict(r) for r in db.execute("SELECT * FROM suspicious_tlds ORDER BY tld")],
    }


@router.post("/patterns/rules", status_code=201)
def add_rule(rule: RuleIn) -> dict:
    if rule.category not in CATEGORIES:
        raise HTTPException(422, f"Unknown category. Use one of: {', '.join(sorted(CATEGORIES))}")
    if rule.category in pattern_store.REGEX_CATEGORIES:
        import re

        try:
            re.compile(rule.value)
        except re.error as exc:
            raise HTTPException(422, f"Invalid regular expression: {exc}") from exc
    db = get_connection()
    with db:
        db.execute(
            "INSERT INTO pattern_rules (category, value, note, source) VALUES (?, ?, ?, 'analyst') "
            "ON CONFLICT(category, value) DO UPDATE SET active = 1, note = COALESCE(excluded.note, note)",
            (rule.category, rule.value if rule.category in pattern_store.REGEX_CATEGORIES else rule.value.lower(), rule.note),
        )
    return _changed()


@router.post("/patterns/brands", status_code=201)
def add_brand(brand: BrandIn) -> dict:
    db = get_connection()
    position = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM brands").fetchone()[0]
    with db:
        db.execute(
            "INSERT INTO brands (name, legit_domains_json, sector, position, source) VALUES (?, ?, ?, ?, 'analyst') "
            "ON CONFLICT(name) DO UPDATE SET legit_domains_json = excluded.legit_domains_json, "
            "sector = COALESCE(excluded.sector, sector), active = 1",
            (brand.name.lower().strip(), json.dumps([d.lower().strip() for d in brand.legit_domains]), brand.sector, position),
        )
    return _changed()


@router.post("/patterns/tlds", status_code=201)
def add_tld(tld: TldIn) -> dict:
    value = "." + tld.tld.lower().strip().lstrip(".")
    db = get_connection()
    with db:
        db.execute(
            "INSERT INTO suspicious_tlds (tld, note, source) VALUES (?, ?, 'analyst') "
            "ON CONFLICT(tld) DO UPDATE SET active = 1, note = COALESCE(excluded.note, note)",
            (value, tld.note),
        )
    return _changed()


@router.post("/patterns/active")
def set_active(change: ActiveIn) -> dict:
    table, column = {
        "rule": ("pattern_rules", "id"),
        "brand": ("brands", "name"),
        "tld": ("suspicious_tlds", "tld"),
    }[change.kind]
    db = get_connection()
    with db:
        updated = db.execute(
            f"UPDATE {table} SET active = ? WHERE {column} = ?", (int(change.active), change.key)
        ).rowcount
    if not updated:
        raise HTTPException(404, "No such pattern.")
    return _changed()


@router.get("/patterns/export")
def export_patterns(source: str | None = None) -> dict:
    """Download patterns in the seed-file format, e.g. to move them into a private pack."""
    db = get_connection()
    where, args = ("WHERE active = 1 AND source = ?", (source,)) if source else ("WHERE active = 1", ())
    return {
        "_about": "ScamRead pattern pack export",
        "version": pattern_store.current().version,
        "rules": [dict(r) for r in db.execute(f"SELECT category, value, note FROM pattern_rules {where} ORDER BY id", args)],
        "brands": [
            {"name": r["name"], "legit_domains": json.loads(r["legit_domains_json"]), "sector": r["sector"]}
            for r in db.execute(f"SELECT * FROM brands {where} ORDER BY position", args)
        ],
        "suspicious_tlds": [dict(r) for r in db.execute(f"SELECT tld, note FROM suspicious_tlds {where} ORDER BY tld", args)],
    }


@router.post("/reload")
def reload_everything() -> dict:
    campaign_store.refresh_index()
    return _changed()


# ---------- campaigns ----------


class CampaignIn(BaseModel):
    campaign_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    title: str = Field(min_length=3, max_length=200)
    status: str = Field(default="active", max_length=40)
    countries: list[str] = Field(default_factory=list, max_length=20)
    impersonated_brand: str | None = Field(default=None, max_length=120)
    threat_type: str | None = Field(default=None, max_length=80)
    cluster: str | None = Field(default=None, max_length=120)
    summary: str | None = Field(default=None, max_length=2000)
    review_status: Literal["unreviewed", "reviewed", "published", "rejected"] = "unreviewed"


class CampaignIndicatorIn(BaseModel):
    indicator_type: Literal[tuple(campaign_store.INDICATOR_TYPES.values())]  # type: ignore[valid-type]
    indicator_value: str = Field(min_length=1, max_length=500)
    first_seen: str | None = None
    last_seen: str | None = None
    source_reference: str | None = Field(default=None, max_length=500)
    confidence: int | None = Field(default=None, ge=0, le=100)


@router.post("/campaigns", status_code=201)
def create_campaign(campaign: CampaignIn) -> dict:
    try:
        campaign_store.create_campaign(**campaign.model_dump())
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "A campaign with this id already exists.") from exc
    results.clear()
    return {"ok": True, "campaign_id": campaign.campaign_id}


@router.post("/campaigns/{campaign_id}/indicators", status_code=201)
def add_campaign_indicator(campaign_id: str, indicator: CampaignIndicatorIn) -> dict:
    try:
        campaign_store.add_campaign_indicator(campaign_id, **indicator.model_dump())
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Unknown campaign or duplicate indicator.") from exc
    results.clear()
    return {"ok": True}


@router.post("/campaigns/{campaign_id}/review")
def set_review_status(
    campaign_id: str, review_status: Literal["unreviewed", "reviewed", "published", "rejected"]
) -> dict:
    db = get_connection()
    with db:
        updated = db.execute(
            "UPDATE campaigns SET review_status = ? WHERE campaign_id = ?", (review_status, campaign_id)
        ).rowcount
    if not updated:
        raise HTTPException(404, "No such campaign.")
    campaign_store.refresh_index()
    results.clear()
    return {"ok": True}
