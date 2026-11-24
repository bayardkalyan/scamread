"""Anonymous scam-pattern statistics, written in the background.

For medium/high-risk results only, this records the *shape* of the scam:
claimed brand, scam types, red-flag IDs, pressure score, link domain endings
and the link domains themselves (the scam infrastructure). It never records the
message text, a hash of it, phone numbers, email addresses, IP addresses or
anything about the person who ran the check.

Writes are queued and flushed every few seconds, so checks never wait on disk.
"""

import hashlib
import json
import logging
import queue
import threading
from datetime import UTC, datetime

from app import config
from app.services.database import get_connection

log = logging.getLogger(__name__)

# Very common legitimate domains that are not useful as scam infrastructure.
COMMON_LEGIT_DOMAINS = {
    "google.com", "youtube.com", "youtu.be", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "wikipedia.org", "gov.in", "nic.in",
    "scamread.com",
}

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10_000)
_stop = threading.Event()
_thread: threading.Thread | None = None


def _tld(hostname: str) -> str:
    return "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""


def _strip_www(hostname: str) -> str:
    return hostname[4:] if hostname.startswith("www.") else hostname


def _is_legit(hostname: str, legit: frozenset[str]) -> bool:
    candidates = legit | COMMON_LEGIT_DOMAINS
    return any(hostname == d or hostname.endswith("." + d) for d in candidates)


def build_observation(analysis: dict, raw_domains: list[str], legit_domains: frozenset[str]) -> dict | None:
    """Turn an analysis result into an anonymous observation, or None if not worth recording."""
    if analysis["risk_score"] < config.RECORD_MIN_RISK_SCORE:
        return None
    hostnames = [_strip_www(h) for h in dict.fromkeys(analysis.get("link_domains", []) + raw_domains) if h]
    scam_hosts = [h for h in hostnames if not _is_legit(h, legit_domains)]
    tlds = sorted({_tld(h) for h in hostnames if _tld(h)})
    return {
        "risk_level": analysis["risk_level"],
        "risk_score": analysis["risk_score"],
        "scam_types": sorted(analysis["suspected_types"]),
        "claimed_brand": analysis.get("claimed_brand"),
        "brand_mismatch": bool(analysis.get("brand_mismatch")),
        "link_tlds": tlds,
        "urgency_score": int(analysis.get("urgency_score", 0)),
        "red_flag_ids": sorted(analysis.get("red_flag_ids", [])),
        "domains": scam_hosts[:10],
    }


def record(observation: dict | None) -> None:
    """Queue an observation; drop it rather than slow a request if the queue is full."""
    if observation is None:
        return
    try:
        _queue.put_nowait(observation)
    except queue.Full:
        log.warning("observation queue full, dropping one observation")


def _signature(obs: dict) -> str:
    key = json.dumps(
        [
            obs["risk_level"],
            obs["scam_types"],
            obs["claimed_brand"],
            obs["brand_mismatch"],
            obs["link_tlds"],
            obs["urgency_score"] // 25 * 25,
            obs["red_flag_ids"],
        ],
        separators=(",", ":"),
    )
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def flush() -> int:
    """Write all queued observations in one transaction. Returns how many were written."""
    batch = []
    while True:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    if not batch:
        return 0
    today = datetime.now(UTC).date().isoformat()
    connection = get_connection()
    with connection:
        for obs in batch:
            connection.execute(
                """
                INSERT INTO pattern_observations (
                    signature, risk_level, scam_types_json, claimed_brand, brand_mismatch,
                    link_tlds_json, urgency_score, red_flag_ids_json, first_seen, last_seen, hits
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(signature) DO UPDATE SET
                    hits = hits + 1,
                    last_seen = excluded.last_seen,
                    urgency_score = MAX(urgency_score, excluded.urgency_score)
                """,
                (
                    _signature(obs),
                    obs["risk_level"],
                    json.dumps(obs["scam_types"]),
                    obs["claimed_brand"],
                    int(obs["brand_mismatch"]),
                    json.dumps(obs["link_tlds"]),
                    obs["urgency_score"],
                    json.dumps(obs["red_flag_ids"]),
                    today,
                    today,
                ),
            )
            for domain in obs["domains"]:
                connection.execute(
                    """
                    INSERT INTO domain_observations (
                        domain, tld, claimed_brand, max_risk_score, first_seen, last_seen, hits
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(domain) DO UPDATE SET
                        hits = hits + 1,
                        last_seen = excluded.last_seen,
                        max_risk_score = MAX(max_risk_score, excluded.max_risk_score),
                        claimed_brand = COALESCE(excluded.claimed_brand, claimed_brand)
                    """,
                    (domain, _tld(domain), obs["claimed_brand"], obs["risk_score"], today, today),
                )
    return len(batch)


def _run() -> None:
    while not _stop.wait(config.OBSERVATION_FLUSH_SECONDS):
        try:
            flush()
        except Exception as exc:  # statistics must never take the app down
            log.error("observation flush failed: %s", exc)


def start() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        _stop.clear()
        _thread = threading.Thread(target=_run, name="observation-writer", daemon=True)
        _thread.start()


def stop() -> None:
    _stop.set()
    try:
        flush()
    except Exception as exc:
        log.error("final observation flush failed: %s", exc)
