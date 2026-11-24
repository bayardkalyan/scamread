"""Admin endpoints for the pattern and campaign database (token required).

Everything here needs  Authorization: Bearer <SCAMREAD_ADMIN_TOKEN>.
If that setting is empty on the server, these endpoints answer 404.
"""

import json
import re
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
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

    today = datetime.now(UTC).date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    per_day = {d: {"low": 0, "medium": 0, "high": 0} for d in days}
    for r in db.execute("SELECT day, risk_level, checks FROM daily_stats WHERE day >= ?", (days[0],)):
        if r["day"] in per_day and r["risk_level"] in per_day[r["day"]]:
            per_day[r["day"]][r["risk_level"]] = r["checks"]
    week = days[-7:]

    def total(ds, levels=("low", "medium", "high")):
        return sum(per_day[d][lv] for d in ds for lv in levels)

    return {
        "summary": {
            "checks_today": total([days[-1]]),
            "checks_7_days": total(week),
            "risky_7_days": total(week, ("medium", "high")),
            "scam_websites": db.execute("SELECT COUNT(*) FROM domain_observations").fetchone()[0],
            "brands_faked": db.execute(
                "SELECT COUNT(DISTINCT claimed_brand) FROM pattern_observations WHERE claimed_brand IS NOT NULL"
            ).fetchone()[0],
            "campaigns_published": db.execute(
                "SELECT COUNT(*) FROM campaigns WHERE review_status = 'published'"
            ).fetchone()[0],
        },
        "daily": [{"day": d, **per_day[d]} for d in days],
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
    # True: value is ordinary words, turned into a safe whole-word pattern.
    # False: value is a Python regular expression (advanced).
    plain: bool = True


def plain_to_pattern(words: str) -> str:
    """'act fast' -> whole-word pattern matching 'act fast' (any spacing)."""
    parts = [re.escape(w) for w in words.lower().split()]
    return r"\b" + r"\s+".join(parts) + r"\b"


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
            for r in db.execute(
                "SELECT * FROM brands ORDER BY CASE source WHEN 'analyst' THEN 0 ELSE 1 END, position, name"
            )
        ],
        "suspicious_tlds": [dict(r) for r in db.execute("SELECT * FROM suspicious_tlds ORDER BY tld")],
    }


@router.post("/patterns/rules", status_code=201)
def add_rule(rule: RuleIn) -> dict:
    if rule.category not in CATEGORIES:
        raise HTTPException(422, f"Unknown category. Use one of: {', '.join(sorted(CATEGORIES))}")
    value = rule.value.strip()
    if not value:
        raise HTTPException(422, "Please type a word or phrase.")
    if rule.category in pattern_store.REGEX_CATEGORIES:
        if rule.plain:
            value = plain_to_pattern(value)
        try:
            re.compile(value)
        except re.error as exc:
            raise HTTPException(422, f"Invalid regular expression: {exc}") from exc
    else:
        value = " ".join(value.lower().split())
    db = get_connection()
    with db:
        db.execute(
            "INSERT INTO pattern_rules (category, value, note, source) VALUES (?, ?, ?, 'analyst') "
            "ON CONFLICT(category, value) DO UPDATE SET active = 1, note = COALESCE(excluded.note, note)",
            (rule.category, value, rule.note),
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
    campaign_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
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

    def model_post_init(self, _context) -> None:
        value = self.indicator_value.strip()
        if self.indicator_type in {"domain", "email_address", "url"}:
            value = value.lower() if self.indicator_type != "url" else value
        if self.indicator_type == "domain":
            value = re.sub(r"^https?://", "", value).split("/")[0].removeprefix("www.")
        self.indicator_value = value

    first_seen: str | None = None
    last_seen: str | None = None
    source_reference: str | None = Field(default=None, max_length=500)
    confidence: int | None = Field(default=None, ge=0, le=100)


def _slug(title: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60] or "campaign"
    return f"{base}-{secrets.token_hex(2)}"


@router.get("/campaigns")
def list_campaigns() -> dict:
    rows = get_connection().execute(
        "SELECT c.*, COUNT(ci.id) AS indicator_count FROM campaigns c "
        "LEFT JOIN campaign_indicators ci ON ci.campaign_id = c.campaign_id "
        "GROUP BY c.campaign_id ORDER BY c.rowid DESC"
    ).fetchall()
    return {
        "campaigns": [
            {**{k: r[k] for k in r.keys() if k != "countries_json"}, "countries": json.loads(r["countries_json"])}
            for r in rows
        ]
    }


@router.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str) -> dict:
    db = get_connection()
    row = db.execute("SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such campaign.")
    indicators = db.execute(
        "SELECT indicator_type, indicator_value, first_seen, last_seen, source_reference, confidence "
        "FROM campaign_indicators WHERE campaign_id = ? ORDER BY id",
        (campaign_id,),
    ).fetchall()
    return {
        "campaign": {**{k: row[k] for k in row.keys() if k != "countries_json"}, "countries": json.loads(row["countries_json"])},
        "indicators": [dict(i) for i in indicators],
    }


class IndicatorKey(BaseModel):
    indicator_type: str
    indicator_value: str


@router.post("/campaigns/{campaign_id}/indicators/remove")
def remove_campaign_indicator(campaign_id: str, key: IndicatorKey) -> dict:
    db = get_connection()
    with db:
        removed = db.execute(
            "DELETE FROM campaign_indicators WHERE campaign_id = ? AND indicator_type = ? AND indicator_value = ?",
            (campaign_id, key.indicator_type, key.indicator_value),
        ).rowcount
    if not removed:
        raise HTTPException(404, "No such indicator.")
    campaign_store.refresh_index()
    results.clear()
    return {"ok": True}


@router.post("/campaigns", status_code=201)
def create_campaign(campaign: CampaignIn) -> dict:
    data = campaign.model_dump()
    data["campaign_id"] = data["campaign_id"] or _slug(campaign.title)
    campaign = CampaignIn(**data)
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
