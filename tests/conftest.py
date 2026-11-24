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
def client():
    from fastapi.testclient import TestClient

    from app.analysis.cache import results
    from app.main import app

    results.clear()
    with TestClient(app) as test_client:
        yield test_client


ADMIN = {"Authorization": "Bearer test-admin-token"}
