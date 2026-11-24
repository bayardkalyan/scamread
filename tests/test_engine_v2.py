from app.analysis import rule_engine
from app.analysis.patterns import pattern_set_from_seed
from app.extractors.regex import extract_indicators

ALL = pattern_set_from_seed()


def run(text, **kwargs):
    return rule_engine.analyze(text, extract_indicators(text), ALL, **kwargs)


def test_link_without_https_is_now_caught():
    text = "Dear customer, your SBI account will be blocked. Update KYC at sbi-kyc.tk/verify"
    old = run(text, bare_domains_as_links=False)
    new = run(text)
    assert new["risk_score"] > old["risk_score"]
    assert new["brand_mismatch"] is True
    assert "Uses a suspicious or unusual domain" in new["red_flags"]
    assert new["link_domains"] == ["sbi-kyc.tk"]


def test_file_names_are_not_links():
    result = run("Please see the attached invoice.pdf and report.docx")
    assert result["link_domains"] == []
    assert "Contains a URL" not in result["red_flags"]


def test_official_domain_is_not_a_mismatch():
    result = run("SBI never asks for OTP. Visit https://onlinesbi.sbi.co.in for help.")
    assert result["claimed_brand"] == "sbi"
    assert result["brand_mismatch"] is False


def test_extended_brand_and_tld():
    result = run("Your Amazon order is on hold. Pay now at https://amaz0n-refund.top/claim")
    assert result["claimed_brand"] == "amazon"
    assert result["brand_mismatch"] is True
    assert result["official_domains"][:2] == ["amazon.com", "amazon.in"]
    assert "Uses a suspicious or unusual domain" in result["red_flags"]


def test_urgency_score_range():
    calm = run("See you at dinner")
    pushy = run("URGENT final warning: act now or your account will be suspended, legal action, arrest")
    assert calm["urgency_score"] == 0
    assert 50 <= pushy["urgency_score"] <= 100
