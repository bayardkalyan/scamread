"""The v2 engine, fed the original ('core') patterns, must score exactly like v1."""

import itertools
import random

import pytest

from app.analysis import rule_engine
from app.analysis.patterns import pattern_set_from_seed
from app.extractors.regex import extract_indicators
from tests.legacy import rule_engine_v0

CORE = pattern_set_from_seed(sets=("core",))
V1_KEYS = ("risk_score", "risk_level", "red_flags", "suspected_types")

FRAGMENTS = [
    "Dear customer,", "Dear user", "URGENT:", "Act now", "within 24 hours", "final warning",
    "your SBI account will be blocked", "State Bank of India", "HDFC Bank", "icici", "Kotak Mahindra",
    "Your account has been suspended", "legal action will be taken", "police action", "pay a fine",
    "share the OTP", "OTP is 448812, do not share", "enter your password", "verify your PIN",
    "Your KYC expired", "update your details", "complete verification", "verify your account",
    "pay Rs 25", "pay ₹49 now", "make a payment", "registration fee", "deposit", "customs fee",
    "Your parcel could not be delivered", "delivery failed", "address is incomplete", "tracking",
    "https://sbi.co.in/login", "http://sbi-kyc-update.tk/verify", "https://hdfcbank.com.secure-login.ml",
    "https://netbanking.hdfcbank.com/", "https://bit.ly/3xYz", "https://example.ga/a?b=c",
    "investment with 30% profit", "crypto returns", "part time job, salary 50000, hiring now",
    "Hi mom, this is my new number", "Meeting at 5pm tomorrow?", "credit card", "customer care",
    "call +91 98765 43210", "mail support@sbi-help.com", "visit sbi-kyc.tk now", "axis",
]

FIXED_CASES = [
    "Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc.tk/update and share OTP.",
    "Your parcel could not be delivered. Pay Rs 25 delivery fee at https://indiapost-track.ga/pay within 24 hours.",
    "Hey, are we still on for lunch tomorrow?",
    "HDFC Bank: Rs 5,000 debited. Not you? Call customer care.",
    "Congratulations! Part-time job, salary 5000/day. Registration fee 499 only. Hiring now!",
    "Invest in crypto and get guaranteed profit of 200% return",
    "https://www.icicibank.com/ is the only official site. Never share your OTP.",
    "",
    "ACCOUNT CLOSED!!! legal action, police action, arrest warrant. pay fine now",
]


def _v1(text):
    return rule_engine_v0.analyze(text, extract_indicators(text))


def _v2(text):
    result = rule_engine.analyze(text, extract_indicators(text), CORE, bare_domains_as_links=False)
    return {k: result[k] for k in V1_KEYS}


@pytest.mark.parametrize("text", FIXED_CASES)
def test_fixed_cases_match_v1(text):
    assert _v2(text) == _v1(text)


def test_all_fragment_pairs_match_v1():
    for a, b in itertools.combinations(FRAGMENTS, 2):
        text = f"{a} {b}"
        assert _v2(text) == _v1(text), text


def test_random_messages_match_v1():
    rng = random.Random(20261124)
    for _ in range(3000):
        text = " ".join(rng.sample(FRAGMENTS, rng.randint(1, 7)))
        if rng.random() < 0.3:
            text = text.upper()
        assert _v2(text) == _v1(text), text
