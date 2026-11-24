import pytest

from app import config
from app.services import admin_auth, observations
from app.services.database import get_connection

H = {"X-ScamRead-Admin": "1"}
PASSWORD = "Correct-Horse-Battery-42"


@pytest.fixture()
def admin(client):
    admin_auth.limiter.clear()
    admin_auth.set_password("BAYARD", PASSWORD)
    client.cookies.clear()
    return client


def login(client, username="BAYARD", password=PASSWORD):
    return client.post("/admin/api/login", json={"username": username, "password": password}, headers=H)


def test_hash_is_salted_and_env_safe():
    a, b = admin_auth.hash_password("same password"), admin_auth.hash_password("same password")
    assert a != b and "$" not in a and a.startswith("scrypt:")
    assert admin_auth.verify_password("same password", a)
    assert not admin_auth.verify_password("other", a)
    assert not admin_auth.verify_password("x", "garbage")


def test_admin_page_is_private(client):
    r = client.get("/admin")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "noindex" in r.headers["x-robots-tag"]
    assert "login-form" in r.text and "googletagmanager" not in r.text


def test_login_flow(admin):
    assert admin.get("/admin/api/me").status_code == 401
    assert login(admin, password="wrong").status_code == 401
    assert login(admin, username="nobody").status_code == 401
    r = login(admin)
    assert r.status_code == 200 and r.json()["username"] == "BAYARD"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert admin.get("/admin/api/me").json() == {"username": "BAYARD"}
    # username is not case-sensitive
    admin.cookies.clear()
    assert login(admin, username="bayard").status_code == 200


def test_cross_site_requests_are_blocked(admin):
    assert admin.post("/admin/api/login", json={"username": "BAYARD", "password": PASSWORD}).status_code == 403
    login(admin)
    # Logged in, but a change without the admin header is refused.
    r = admin.post("/api/admin/patterns/tlds", json={"tld": ".evil"})
    assert r.status_code == 403
    assert admin.post("/api/admin/patterns/tlds", json={"tld": ".evil"}, headers=H).status_code == 201


def test_lockout_after_repeated_failures(admin):
    for _ in range(config.LOGIN_MAX_FAILURES):
        assert login(admin, password="nope").status_code == 401
    r = login(admin)  # even the right password is refused while locked
    assert r.status_code == 429 and "retry-after" in r.headers


def test_logout_and_password_change(admin):
    login(admin)
    r = admin.post("/admin/api/password", json={"current_password": "wrong", "new_password": "a-brand-new-pass"}, headers=H)
    assert r.status_code == 401
    r = admin.post("/admin/api/password", json={"current_password": PASSWORD, "new_password": "short"}, headers=H)
    assert r.status_code == 422
    r = admin.post("/admin/api/password", json={"current_password": PASSWORD, "new_password": "a-brand-new-pass"}, headers=H)
    assert r.status_code == 200
    assert admin.get("/admin/api/me").status_code == 200  # this browser got a fresh session
    admin.post("/admin/api/logout", headers=H)
    assert admin.get("/admin/api/me").status_code == 401
    assert login(admin).status_code == 401
    assert login(admin, password="a-brand-new-pass").status_code == 200


def test_bootstrap_admin_from_settings(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USER", "FIRSTADMIN")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", admin_auth.hash_password("first-admin-password"))
    admin_auth.ensure_bootstrap_admin()
    assert admin_auth.check_credentials("firstadmin", "first-admin-password") == "FIRSTADMIN"


def test_plain_words_become_whole_word_rules(admin):
    login(admin)
    text = "Hello, please ACT   FAST on this offer"
    before = admin.post("/api/analyze", json={"text": text}).json()["analysis"]
    assert "Uses urgent or pressure-based language" not in before["red_flags"]
    r = admin.post("/api/admin/patterns/rules", json={"category": "urgency", "value": "Act fast"}, headers=H)
    assert r.status_code == 201
    after = admin.post("/api/analyze", json={"text": text}).json()["analysis"]
    assert "Uses urgent or pressure-based language" in after["red_flags"]
    # whole words only: "contact fastly" must not match
    other = admin.post("/api/analyze", json={"text": "contact fastly support"}).json()["analysis"]
    assert "Uses urgent or pressure-based language" not in other["red_flags"]


def test_campaign_matching_by_phone_and_subdomain(admin):
    login(admin)
    r = admin.post("/api/admin/campaigns", json={"title": "Fake SBI KYC texts (Nov 2026)", "impersonated_brand": "SBI"}, headers=H)
    assert r.status_code == 201
    cid = r.json()["campaign_id"]
    assert cid.startswith("fake-sbi-kyc-texts-nov-2026-")
    for t, v in [("phone_number", "+91 98765 43210"), ("domain", "https://www.SBI-Rewards.tk/claim")]:
        assert admin.post(f"/api/admin/campaigns/{cid}/indicators", json={"indicator_type": t, "indicator_value": v}, headers=H).status_code == 201
    detail = admin.get(f"/api/admin/campaigns/{cid}").json()
    assert {i["indicator_value"] for i in detail["indicators"]} == {"+91 98765 43210", "sbi-rewards.tk"}

    msg = "Claim your SBI points at http://login.sbi-rewards.tk/x or call 098765-43210"
    assert admin.post("/api/analyze", json={"text": msg}).json()["campaign"]["matched"] is False  # still a draft
    assert admin.post(f"/api/admin/campaigns/{cid}/review?review_status=published", headers=H).status_code == 200
    data = admin.post("/api/analyze", json={"text": msg}).json()
    assert data["campaign"]["matched"] is True
    matched = {i["indicator_value"] for i in data["campaign"]["campaign"]["matched_indicators"]}
    assert matched == {"+91 98765 43210", "sbi-rewards.tk"}
    listing = admin.get("/api/admin/campaigns").json()["campaigns"]
    assert any(c["campaign_id"] == cid and c["indicator_count"] == 2 for c in listing)
    r = admin.post(f"/api/admin/campaigns/{cid}/indicators/remove", json={"indicator_type": "domain", "indicator_value": "sbi-rewards.tk"}, headers=H)
    assert r.status_code == 200


def test_daily_counts_include_repeat_checks(admin):
    db = get_connection()
    def today_total():
        return db.execute("SELECT COALESCE(SUM(checks),0) FROM daily_stats WHERE day = date('now')").fetchone()[0]
    observations.flush()
    before = today_total()
    for _ in range(3):
        admin.post("/api/analyze", json={"text": "same message counted three times"})
    observations.flush()
    assert today_total() == before + 3
    login(admin)
    stats = admin.get("/api/admin/stats").json()
    assert len(stats["daily"]) == 14 and stats["summary"]["checks_today"] >= 3
