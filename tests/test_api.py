import json

from app.services import observations
from app.services.database import get_connection
from tests.conftest import ADMIN

SCAM = (
    "Dear Customer, your SBI account will be blocked today. Update KYC immediately at "
    "http://sbi-kyc.tk/update and share OTP. Call +91 98765 43210 or mail help@sbi-care.com"
)


def test_page_and_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "content-security-policy" in page.headers
    assert "analysis-form" in page.text and "G-S8ZVKZM7C6" in page.text
    css = client.get("/static/css/app.css?v=x")
    assert css.status_code == 200
    assert "immutable" in css.headers["cache-control"]


def test_analyze_shape_is_backwards_compatible(client):
    data = client.post("/api/analyze", json={"text": SCAM}).json()
    assert set(data) == {"indicators", "total_indicators", "analysis", "campaign"}
    for key in ("risk_score", "risk_level", "red_flags", "suspected_types"):
        assert key in data["analysis"]
    assert data["analysis"]["risk_level"] == "high"
    assert data["campaign"] == {"matched": False, "campaign": None, "confidence": 0}
    assert "red_flag_ids" not in data["analysis"]


def test_validation(client):
    assert client.post("/api/analyze", json={"text": "   "}).status_code == 422
    assert client.post("/api/analyze", json={"text": "x" * 20_001}).status_code == 422


def test_repeat_is_served_from_cache(client):
    from app.analysis.cache import results

    first = client.post("/api/analyze", json={"text": "cache me URGENT"}).content
    hits = results.hits
    second = client.post("/api/analyze", json={"text": "cache me URGENT"}).content
    assert first == second
    assert results.hits == hits + 1


def test_no_message_text_or_personal_data_is_stored(client):
    client.post("/api/analyze", json={"text": SCAM + " unique-marker-7781"})
    observations.flush()
    db = get_connection()
    dump = "\n".join(db.iterdump())
    for secret in ("unique-marker-7781", "98765", "help@sbi-care.com", "Dear Customer", "blocked today"):
        assert secret not in dump
    # ...but the scam shape and the scam domain are recorded.
    shape = db.execute("SELECT * FROM pattern_observations WHERE claimed_brand = 'sbi'").fetchone()
    assert shape is not None and json.loads(shape["link_tlds_json"]) == [".tk"]
    assert db.execute("SELECT 1 FROM domain_observations WHERE domain = 'sbi-kyc.tk'").fetchone()


def test_low_risk_messages_are_not_recorded(client):
    db = get_connection()
    before = db.execute("SELECT COALESCE(SUM(hits),0) FROM pattern_observations").fetchone()[0]
    client.post("/api/analyze", json={"text": "Lunch at 1? I'll book the table."})
    observations.flush()
    after = db.execute("SELECT COALESCE(SUM(hits),0) FROM pattern_observations").fetchone()[0]
    assert before == after


def test_old_test_endpoint_is_gone(client):
    assert client.post("/api/test/rule-engine", json={"text": "hi"}).status_code in (404, 405)


def test_admin_endpoints_need_the_token(client):
    assert client.get("/api/admin/stats").status_code == 401
    assert client.get("/api/admin/stats", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/intelligence/capture", json={"text": SCAM}).status_code == 401
    stats = client.get("/api/admin/stats", headers=ADMIN)
    assert stats.status_code == 200 and "top_brands" in stats.json()


def test_admin_can_add_a_brand_and_it_takes_effect(client):
    text = "Your Zomato wallet is blocked, verify at https://zomato-gift.top/x"
    before = client.post("/api/analyze", json={"text": text}).json()["analysis"]
    assert before["claimed_brand"] is None
    r = client.post(
        "/api/admin/patterns/brands",
        headers=ADMIN,
        json={"name": "Zomato", "legit_domains": ["zomato.com"], "sector": "food"},
    )
    assert r.status_code == 201
    after = client.post("/api/analyze", json={"text": text}).json()["analysis"]
    assert after["claimed_brand"] == "zomato" and after["brand_mismatch"] is True
    assert after["risk_score"] > before["risk_score"]


def test_bad_regex_is_rejected(client):
    r = client.post("/api/admin/patterns/rules", headers=ADMIN, json={"category": "urgency", "value": "(unclosed", "plain": False})
    assert r.status_code == 422


def test_published_campaign_matches(client):
    r = client.post(
        "/api/admin/campaigns",
        headers=ADMIN,
        json={"campaign_id": "sbi-kyc-tk-2026", "title": "SBI KYC .tk wave", "review_status": "published"},
    )
    assert r.status_code == 201
    r = client.post(
        "/api/admin/campaigns/sbi-kyc-tk-2026/indicators",
        headers=ADMIN,
        json={"indicator_type": "domain", "indicator_value": "sbi-kyc.tk"},
    )
    assert r.status_code == 201
    data = client.post("/api/analyze", json={"text": SCAM}).json()
    assert data["campaign"]["matched"] is True
    assert data["campaign"]["campaign"]["campaign"]["campaign_id"] == "sbi-kyc-tk-2026"


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"
