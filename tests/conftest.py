import os
import tempfile
from pathlib import Path

import pytest

# Use a throwaway database and development mode for every test run.
_tmp = tempfile.mkdtemp(prefix="scamread-test-")
os.environ["SCAMREAD_DATABASE_PATH"] = str(Path(_tmp) / "test.db")
os.environ["SCAMREAD_ENV"] = "development"
os.environ["SCAMREAD_ADMIN_TOKEN"] = "test-admin-token"
os.environ["SCAMREAD_OBSERVATION_FLUSH_SECONDS"] = "3600"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A test client with its own empty database, so tests can't affect each other."""
    from fastapi.testclient import TestClient

    from app import config
    from app.analysis.cache import results
    from app.main import app
    from app.services import admin_auth, database

    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "test.db")
    database.reset_for_tests()
    results.clear()
    admin_auth.limiter.clear()
    with TestClient(app) as test_client:
        yield test_client
    database.reset_for_tests()


ADMIN = {"Authorization": "Bearer test-admin-token"}
