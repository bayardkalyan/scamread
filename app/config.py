"""Runtime settings, read once from environment variables.

Production is the safe default: API docs are hidden and admin endpoints stay
closed unless an admin token is configured.
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


ENVIRONMENT = os.environ.get("SCAMREAD_ENV", "production").strip().lower()
IS_PRODUCTION = ENVIRONMENT != "development"

# Database: SQLite file outside git. Holds patterns and anonymous pattern
# statistics only, never submitted message text.
DATABASE_PATH = Path(
    os.environ.get("SCAMREAD_DATABASE_PATH", PROJECT_ROOT / "data" / "scamread.db")
)

# Open-source starter patterns shipped with the code.
SEED_PATTERNS_FILE = PROJECT_ROOT / "app" / "seed" / "patterns.json"

# Optional private pattern packs (JSON files in the same format as the seed
# file), kept outside this repository. This is how detection rules can be
# kept private later without changing code.
PRIVATE_PATTERNS_DIR = os.environ.get("SCAMREAD_PRIVATE_PATTERNS_DIR", "").strip()

# Admin token for write endpoints. Unset means admin endpoints are disabled.
ADMIN_TOKEN = os.environ.get("SCAMREAD_ADMIN_TOKEN", "").strip()

# Result cache: results kept in memory only, keyed by a hash of the text.
CACHE_TTL_SECONDS = _int("SCAMREAD_CACHE_TTL_SECONDS", 900)
CACHE_MAX_ENTRIES = _int("SCAMREAD_CACHE_MAX_ENTRIES", 5000)

# How often patterns and campaigns are reloaded from the database.
PATTERN_RELOAD_SECONDS = _int("SCAMREAD_PATTERN_RELOAD_SECONDS", 300)

# Pattern statistics are written in the background in small batches.
OBSERVATION_FLUSH_SECONDS = _int("SCAMREAD_OBSERVATION_FLUSH_SECONDS", 5)
RECORD_MIN_RISK_SCORE = _int("SCAMREAD_RECORD_MIN_RISK_SCORE", 40)

# Bump to make browsers fetch new CSS/JS after a deploy.
ASSET_VERSION = os.environ.get("SCAMREAD_ASSET_VERSION", "2026.11.24")
