"""Detection patterns: loaded from the database, compiled once, reloaded periodically.

The database is seeded from app/seed/patterns.json (open source). Extra rules
can come from analysts (admin API) or private pattern packs kept outside this
repository (SCAMREAD_PRIVATE_PATTERNS_DIR). The scoring logic lives in
rule_engine.py; this module only supplies the word lists and regexes.
"""

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from app import config
from app.services.database import get_connection

log = logging.getLogger(__name__)

REGEX_CATEGORIES = {"urgency", "threat", "sensitive_request", "financial", "kyc"}
TERM_CATEGORIES = {
    "sensitive_term",
    "banking_term",
    "delivery_context",
    "delivery_problem",
    "generic_greeting",
    "type_investment",
    "type_job",
    "type_delivery",
}
CATEGORIES = REGEX_CATEGORIES | TERM_CATEGORIES


@dataclass(frozen=True)
class Brand:
    name: str
    pattern: re.Pattern
    legit_domains: tuple[str, ...]


@dataclass(frozen=True)
class PatternSet:
    regex: dict[str, tuple[re.Pattern, ...]]
    terms: dict[str, tuple[str, ...]]
    brands: tuple[Brand, ...]
    suspicious_tlds: tuple[str, ...]
    all_legit_domains: frozenset[str] = field(default_factory=frozenset)
    loaded_at: float = 0.0
    # Fingerprint of the pattern content; changes only when the patterns change.
    version: str = ""

    def r(self, category: str) -> tuple[re.Pattern, ...]:
        return self.regex.get(category, ())

    def t(self, category: str) -> tuple[str, ...]:
        return self.terms.get(category, ())


def build_pattern_set(rules, brands, tlds) -> PatternSet:
    """Compile rows (category, value) / brand tuples into a ready-to-use PatternSet."""
    regex: dict[str, list[re.Pattern]] = {c: [] for c in REGEX_CATEGORIES}
    terms: dict[str, list[str]] = {c: [] for c in TERM_CATEGORIES}
    for category, value in rules:
        if category in REGEX_CATEGORIES:
            try:
                regex[category].append(re.compile(value))
            except re.error as exc:  # a bad analyst pattern must never break checks
                log.warning("skipping invalid %s pattern %r: %s", category, value, exc)
        elif category in TERM_CATEGORIES:
            terms[category].append(value.lower())
    compiled_brands = tuple(
        Brand(name, re.compile(rf"\b{re.escape(name)}\b"), tuple(d.lower() for d in domains))
        for name, domains in brands
    )
    legit = frozenset(d for b in compiled_brands for d in b.legit_domains)
    version = hashlib.sha1(
        json.dumps([list(rules), [[n, list(d)] for n, d in brands], list(tlds)]).encode("utf-8")
    ).hexdigest()[:12]
    return PatternSet(
        regex={k: tuple(v) for k, v in regex.items()},
        terms={k: tuple(v) for k, v in terms.items()},
        brands=compiled_brands,
        suspicious_tlds=tuple(t.lower() for t in tlds),
        all_legit_domains=legit,
        loaded_at=time.time(),
        version=version,
    )


def pattern_set_from_seed(path: Path = config.SEED_PATTERNS_FILE, sets=("core", "extended")) -> PatternSet:
    """Build patterns straight from a seed file (used by tests and as a fallback)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [(r["category"], r["value"]) for r in data["rules"] if r.get("set", "core") in sets]
    brands = [(b["name"], b["legit_domains"]) for b in data["brands"] if b.get("set", "core") in sets]
    tlds = [t["tld"] for t in data["suspicious_tlds"] if t.get("set", "core") in sets]
    return build_pattern_set(rules, brands, tlds)


def _import_pack(connection, data: dict, source: str) -> None:
    """Insert a pattern pack. Existing rows are left alone, so a rule an analyst
    switched off stays off after restarts."""
    with connection:
        connection.executemany(
            "INSERT OR IGNORE INTO pattern_rules (category, value, note, source) VALUES (?, ?, ?, ?)",
            [
                (r["category"], r["value"], r.get("note") or r.get("set"), source)
                for r in data.get("rules", [])
                if r.get("category") in CATEGORIES and r.get("value")
            ],
        )
        connection.executemany(
            "INSERT OR IGNORE INTO brands (name, legit_domains_json, sector, position, source) VALUES (?, ?, ?, ?, ?)",
            [
                (b["name"].lower(), json.dumps(b["legit_domains"]), b.get("sector"), position, source)
                for position, b in enumerate(data.get("brands", []))
                if b.get("name") and b.get("legit_domains")
            ],
        )
        connection.executemany(
            "INSERT OR IGNORE INTO suspicious_tlds (tld, note, source) VALUES (?, ?, ?)",
            [
                ("." + t["tld"].lower().lstrip("."), t.get("note") or t.get("set"), source)
                for t in data.get("suspicious_tlds", [])
                if t.get("tld")
            ],
        )


def seed_database() -> None:
    """Load the open-source seed and any private packs into the database."""
    connection = get_connection()
    _import_pack(connection, json.loads(config.SEED_PATTERNS_FILE.read_text(encoding="utf-8")), "seed")
    if config.PRIVATE_PATTERNS_DIR:
        for pack in sorted(Path(config.PRIVATE_PATTERNS_DIR).glob("*.json")):
            try:
                _import_pack(connection, json.loads(pack.read_text(encoding="utf-8")), "private")
                log.info("loaded private pattern pack %s", pack.name)
            except (OSError, ValueError, KeyError) as exc:
                log.warning("could not load private pattern pack %s: %s", pack, exc)


def load_from_database() -> PatternSet:
    connection = get_connection()
    rules = connection.execute(
        "SELECT category, value FROM pattern_rules WHERE active = 1 ORDER BY id"
    ).fetchall()
    brands = connection.execute(
        "SELECT name, legit_domains_json FROM brands WHERE active = 1 "
        "ORDER BY CASE source WHEN 'seed' THEN 0 WHEN 'private' THEN 1 ELSE 2 END, position, name"
    ).fetchall()
    tlds = connection.execute("SELECT tld FROM suspicious_tlds WHERE active = 1 ORDER BY tld").fetchall()
    return build_pattern_set(
        [(r["category"], r["value"]) for r in rules],
        [(b["name"], json.loads(b["legit_domains_json"])) for b in brands],
        [t["tld"] for t in tlds],
    )


_current: PatternSet | None = None
_lock = threading.Lock()


def current() -> PatternSet:
    """Return the active patterns, reloading from the database when they are stale."""
    global _current
    patterns = _current
    if patterns is not None and time.time() - patterns.loaded_at < config.PATTERN_RELOAD_SECONDS:
        return patterns
    with _lock:
        if _current is None or time.time() - _current.loaded_at >= config.PATTERN_RELOAD_SECONDS:
            try:
                _current = load_from_database()
            except Exception as exc:  # database trouble must not stop checks
                log.error("pattern reload failed, using previous/seed patterns: %s", exc)
                _current = _current or pattern_set_from_seed()
        return _current


def reload_now() -> PatternSet:
    global _current
    with _lock:
        _current = load_from_database()
        return _current
