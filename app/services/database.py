"""SQLite access: schema setup runs once at startup, not on every request.

SQLite suits a single small server well. Each worker thread keeps its own
connection, so requests do not pay the cost of opening one.
"""

import sqlite3
import threading

from app import config

_local = threading.local()
_schema_lock = threading.Lock()
_schema_ready = False

SCHEMA = """
-- Analyst-reviewed intelligence (kept from the original app).
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

-- Detection patterns. Seeded from app/seed/patterns.json and extendable by
-- analysts or private pattern packs without code changes.
CREATE TABLE IF NOT EXISTS pattern_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    note TEXT,
    source TEXT NOT NULL DEFAULT 'seed',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (category, value)
);

CREATE TABLE IF NOT EXISTS brands (
    name TEXT PRIMARY KEY,
    legit_domains_json TEXT NOT NULL,
    sector TEXT,
    position INTEGER NOT NULL DEFAULT 1000,
    source TEXT NOT NULL DEFAULT 'seed',
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS suspicious_tlds (
    tld TEXT PRIMARY KEY,
    note TEXT,
    source TEXT NOT NULL DEFAULT 'seed',
    active INTEGER NOT NULL DEFAULT 1
);

-- Anonymous pattern statistics. One row per pattern signature, counted.
-- No message text, no text hashes, no phone numbers, emails, IPs or users.
CREATE TABLE IF NOT EXISTS pattern_observations (
    signature TEXT PRIMARY KEY,
    risk_level TEXT NOT NULL,
    scam_types_json TEXT NOT NULL,
    claimed_brand TEXT,
    brand_mismatch INTEGER NOT NULL DEFAULT 0,
    link_tlds_json TEXT NOT NULL,
    urgency_score INTEGER NOT NULL,
    red_flag_ids_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1
);

-- Link domains seen in medium/high-risk messages (the scam infrastructure),
-- excluding the real domains of the brands being claimed.
CREATE TABLE IF NOT EXISTS domain_observations (
    domain TEXT PRIMARY KEY,
    tld TEXT NOT NULL,
    claimed_brand TEXT,
    max_risk_score INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_pattern_obs_brand ON pattern_observations(claimed_brand);
CREATE INDEX IF NOT EXISTS idx_domain_obs_last_seen ON domain_observations(last_seen);
"""


def _connect() -> sqlite3.Connection:
    config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(config.DATABASE_PATH, timeout=5, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def ensure_schema() -> None:
    """Create tables once per process (safe to call repeatedly)."""
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        connection = _connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)
            connection.commit()
        finally:
            connection.close()
        _schema_ready = True


def get_connection() -> sqlite3.Connection:
    """Return this thread's open connection, creating it on first use."""
    ensure_schema()
    connection = getattr(_local, "connection", None)
    if connection is None or getattr(_local, "path", None) != config.DATABASE_PATH:
        connection = _connect()
        _local.connection = connection
        _local.path = config.DATABASE_PATH
    return connection


def reset_for_tests() -> None:
    """Forget cached connections and schema state (used when tests switch databases)."""
    global _schema_ready
    connection = getattr(_local, "connection", None)
    if connection is not None:
        connection.close()
    _local.connection = None
    _local.path = None
    _schema_ready = False
