"""
Rule-based scam analysis.

This module detects suspicious patterns and combines them
into a weighted risk assessment.
"""

import re
from urllib.parse import urlparse


def analyze(text: str, indicators) -> dict:
    text_lower = text.lower()

    score = 0
    red_flags = []
    scam_types = []

    # ---------------------------------------------------------
    # 1. Urgency / pressure
    # ---------------------------------------------------------

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\bright away\b",
        r"\bwithin\s+\d+\s*(?:hours?|hrs?)\b",
        r"\bfinal warning\b",
        r"\basap\b",
        r"\btoday only\b",
    ]

    if any(re.search(pattern, text_lower) for pattern in urgency_patterns):
        score += 10
        red_flags.append("Uses urgent or pressure-based language")

    # ---------------------------------------------------------
    # 2. Threats / consequences
    # ---------------------------------------------------------

    threat_patterns = [
        r"\baccount.*\bclosed\b",
        r"\baccount.*\bsuspended\b",
        r"\baccount.*\bblocked\b",
        r"\bpermanent suspension\b",
        r"\baccount closure\b",
        r"\blegal action\b",
        r"\bpolice action\b",
        r"\barrest\b",
        r"\bpenalty\b",
        r"\bfine\b",
    ]

    if any(re.search(pattern, text_lower) for pattern in threat_patterns):
        score += 15
        red_flags.append(
            "Uses threats or consequences to pressure the recipient"
        )

    # ---------------------------------------------------------
    # 3. Sensitive information
    # ---------------------------------------------------------

    sensitive_terms = [
        "otp",
        "one-time password",
        "password",
        "bank details",
        "card number",
        "cvv",
        "pin",
        "verification code",
    ]

    sensitive_mentioned = any(
        term in text_lower for term in sensitive_terms
    )

    sensitive_request_patterns = [
        r"\b(?:share|send|provide|give|tell|confirm|enter|submit|verify)\b"
        r".{0,40}\b(?:otp|one[- ]time password|password|cvv|pin|verification code)\b",

        r"\b(?:otp|one[- ]time password|password|cvv|pin|verification code)\b"
        r".{0,40}\b(?:share|send|provide|give|tell|confirm|enter|submit|verify)\b",
    ]

    sensitive_requested = any(
        re.search(pattern, text_lower)
        for pattern in sensitive_request_patterns
    )

    if sensitive_requested:
        score += 40
        red_flags.append(
            "Requests sensitive information such as an OTP, password, or PIN"
        )
    elif sensitive_mentioned:
        score += 10
        red_flags.append(
            "Mentions sensitive information such as an OTP or verification code"
        )

    # ---------------------------------------------------------
    # 4. Financial request
    # ---------------------------------------------------------

    financial_patterns = [
        r"\bsend money\b",
    r"\btransfer money\b",
    r"\bmake a payment\b",
    r"\bpay now\b",
    r"\bpay\s+(?:₹|\$|€|£)?\s*\d+",
    r"\bpayment\b",
    r"\bdeposit\b",
    r"\bfee\b",
    r"\bregistration fee\b",
    r"\bdelivery fee\b",
    r"\bcustoms fee\b",
    r"\bpayment required\b",
    ]

    if any(re.search(pattern, text_lower) for pattern in financial_patterns):
        score += 20
        red_flags.append(
            "Contains a financial request or payment-related language"
        )

   

    # ---------------------------------------------------------
    # 5. Banking context
    # ---------------------------------------------------------

    banking_terms = [
        "bank",
        "bank account",
        "customer care",
        "customer support",
        "credit card",
        "debit card",
        "net banking",
        "internet banking",
        "kyc",
        "account",
    ]

    banking_context = any(
        term in text_lower for term in banking_terms
    )

    if banking_context:
        score += 5

    # ---------------------------------------------------------
    # 6. KYC / verification pretext
    # ---------------------------------------------------------

    kyc_patterns = [
        r"\bkyc\b",
        r"\bkyc expiry\b",
        r"\bkyc expired\b",
        r"\bverify your account\b",
        r"\bverification required\b",
        r"\bcomplete verification\b",
        r"\bupdate your details\b",
    ]

    kyc_context = any(
        re.search(pattern, text_lower)
        for pattern in kyc_patterns
    )

    if kyc_context:
        score += 10
        red_flags.append(
            "Uses KYC or account-verification language"
        )

    # ---------------------------------------------------------
    # 7. URL
    # ---------------------------------------------------------

    has_url = bool(indicators.urls)

    if has_url:
        score += 5
        red_flags.append("Contains a URL")


 # ---------------------------------------------------------
    # 5. Delivery scam context
    # ---------------------------------------------------------

    delivery_context = any(
        term in text_lower
        for term in [
            "parcel",
            "package",
            "delivery",
            "shipment",
            "courier",
            "consignment",
            "tracking",
        ]
    )

    delivery_payment = any(
        re.search(pattern, text_lower)
        for pattern in financial_patterns
    )

    delivery_problem = any(
        phrase in text_lower
        for phrase in [
            "could not be delivered",
            "delivery failed",
            "address is incomplete",
            "address is incorrect",
            "reschedule delivery",
            "delivery fee",
            "customs fee",
        ]
    )

    if delivery_context and (
        delivery_payment
        or delivery_problem
        or has_url
    ):
        score += 35
        red_flags.append(
            "Uses a delivery or parcel problem to request payment or direct the recipient to a link"
        )

        if delivery_payment and has_url:
            score += 15
            red_flags.append(
                "Combines a delivery problem, payment request, and external link"
            )
    # ---------------------------------------------------------
    # 8. Suspicious URL characteristics
    # ---------------------------------------------------------

    suspicious_tlds = {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
    }

    suspicious_url = False

    for url in indicators.urls:
        candidate = url

        if not candidate.startswith(("http://", "https://")):
            candidate = "http://" + candidate

        try:
            hostname = urlparse(candidate).hostname or ""
        except ValueError:
            hostname = ""

        hostname = hostname.lower()

        if any(hostname.endswith(tld) for tld in suspicious_tlds):
            suspicious_url = True
            break

    if suspicious_url:
        score += 15
        red_flags.append(
            "Uses a suspicious or unusual domain"
        )

    # ---------------------------------------------------------
    # 9. Brand impersonation
    # ---------------------------------------------------------

    known_brands = {
        "sbi": ["sbi.co.in"],
        "state bank of india": ["sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
        "hdfc bank": ["hdfcbank.com"],
        "icici": ["icicibank.com"],
        "icici bank": ["icicibank.com"],
        "axis": ["axisbank.com"],
        "axis bank": ["axisbank.com"],
        "kotak": ["kotak.com"],
        "kotak mahindra": ["kotak.com"],
    }

    claimed_brand = None
    legitimate_domains = []

    for brand, domains in known_brands.items():
        if re.search(rf"\b{re.escape(brand)}\b", text_lower):
            claimed_brand = brand
            legitimate_domains = domains
            break

    brand_mismatch = False

    if claimed_brand and has_url:
        for url in indicators.urls:
            candidate = url

            if not candidate.startswith(("http://", "https://")):
                candidate = "http://" + candidate

            try:
                hostname = urlparse(candidate).hostname or ""
            except ValueError:
                hostname = ""

            hostname = hostname.lower()

            if not any(
                hostname == domain or hostname.endswith("." + domain)
                for domain in legitimate_domains
            ):
                brand_mismatch = True
                break

    if brand_mismatch:
        score += 25
        red_flags.append(
            "The message claims to represent a known brand but uses a different domain"
        )

    # ---------------------------------------------------------
    # 10. Generic greeting
    # ---------------------------------------------------------

    generic_greetings = [
        "dear user",
        "dear customer",
        "dear sir",
        "dear madam",
        "valued customer",
    ]

    if any(greeting in text_lower for greeting in generic_greetings):
        score += 5
        red_flags.append("Uses a generic greeting")

    # ---------------------------------------------------------
    # 11. Combination rules
    # ---------------------------------------------------------

    # Banking + OTP request is a particularly strong signal.
    if banking_context and sensitive_requested:
        score += 30
        red_flags.append(
            "Combines banking context with a request for sensitive information"
        )

    # Banking + URL.
    if banking_context and has_url:
        score += 10
        red_flags.append(
            "Combines banking context with an external link"
        )

    # Banking + threat + URL.
    if banking_context and has_url and brand_mismatch:
        score += 15

    # KYC + threat + URL.
    if kyc_context and has_url and any(
        re.search(pattern, text_lower)
        for pattern in threat_patterns
    ):
        score += 15
        red_flags.append(
            "Combines KYC pressure, account consequences, and a link"
        )

    # ---------------------------------------------------------
    # 12. Scam categories
    # ---------------------------------------------------------

    if sensitive_requested and banking_context:
        scam_types.append("credential_phishing")
    elif sensitive_requested:
        scam_types.append("credential_phishing")

    if banking_context and (has_url or sensitive_requested or kyc_context):
        scam_types.append("banking_phishing")

    if any(
        word in text_lower
        for word in ["investment", "profit", "return", "crypto"]
    ):
        scam_types.append("investment_or_crypto")

    if any(
        word in text_lower
        for word in ["job", "salary", "vacancy", "hiring"]
    ):
        scam_types.append("job_scam")

    if any(
        word in text_lower
        for word in ["parcel", "package", "delivery", "shipment"]
    ):
        scam_types.append("delivery_scam")

    # Remove duplicate categories while preserving order.
    scam_types = list(dict.fromkeys(scam_types))

    # ---------------------------------------------------------
    # 13. Final score and risk level
    # ---------------------------------------------------------

    score = min(score, 100)

    if score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not red_flags:
        red_flags.append(
            "No obvious suspicious patterns detected"
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "suspected_types": scam_types,
    }