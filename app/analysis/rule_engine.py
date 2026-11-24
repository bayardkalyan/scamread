"""
Rule-based scam analysis.

This module detects suspicious patterns and combines them into a weighted
risk assessment. The scoring steps are the same as the original engine; the
word lists and regexes now come from the pattern database (see patterns.py),
compiled once instead of on every request.
"""

from urllib.parse import urlparse

from app.analysis import patterns as pattern_store
from app.analysis.patterns import PatternSet

# Stable IDs for red flags, used in anonymous pattern statistics.
FLAG_IDS = {
    "Uses urgent or pressure-based language": "urgency",
    "Uses threats or consequences to pressure the recipient": "threat",
    "Requests sensitive information such as an OTP, password, or PIN": "sensitive_request",
    "Mentions sensitive information such as an OTP or verification code": "sensitive_mention",
    "Contains a financial request or payment-related language": "financial",
    "Uses KYC or account-verification language": "kyc",
    "Contains a URL": "url",
    "Uses a delivery or parcel problem to request payment or direct the recipient to a link": "delivery",
    "Combines a delivery problem, payment request, and external link": "delivery_payment_link",
    "Uses a suspicious or unusual domain": "suspicious_tld",
    "The message claims to represent a known brand but uses a different domain": "brand_mismatch",
    "Uses a generic greeting": "generic_greeting",
    "Combines banking context with a request for sensitive information": "banking_sensitive",
    "Combines banking context with an external link": "banking_link",
    "Combines KYC pressure, account consequences, and a link": "kyc_threat_link",
}


def _hostname(url: str) -> str:
    candidate = url if url.startswith(("http://", "https://")) else "http://" + url
    try:
        return (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _any_regex(compiled, text: str) -> bool:
    return any(p.search(text) for p in compiled)


# Bare "domains" that are really file names, not websites.
FILE_EXTENSIONS = {
    "pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "jpg", "jpeg",
    "png", "gif", "webp", "heic", "mp3", "mp4", "mov", "avi", "html", "htm", "php",
    "js", "py", "json", "xml", "apk", "exe", "rar", "7z",
}


def bare_link_hosts(indicators) -> list[str]:
    """Website addresses written without http(s)://, e.g. 'sbi-kyc.tk/verify'."""
    url_hosts = {_hostname(url) for url in indicators.urls}
    return [
        domain
        for domain in indicators.domains
        if domain not in url_hosts and domain.rsplit(".", 1)[-1] not in FILE_EXTENSIONS
    ]


def analyze(
    text: str,
    indicators,
    patterns: PatternSet | None = None,
    bare_domains_as_links: bool = True,
) -> dict:
    """Score a message.

    bare_domains_as_links=False reproduces the original engine exactly (only
    http/https links counted); True also counts addresses written without it.
    """
    p = patterns or pattern_store.current()
    text_lower = text.lower()

    score = 0
    red_flags = []
    scam_types = []

    # 1. Urgency / pressure
    urgency_hits = sum(1 for pattern in p.r("urgency") if pattern.search(text_lower))
    if urgency_hits:
        score += 10
        red_flags.append("Uses urgent or pressure-based language")

    # 2. Threats / consequences
    threat_hits = sum(1 for pattern in p.r("threat") if pattern.search(text_lower))
    if threat_hits:
        score += 15
        red_flags.append("Uses threats or consequences to pressure the recipient")

    # 3. Sensitive information
    sensitive_mentioned = any(term in text_lower for term in p.t("sensitive_term"))
    sensitive_requested = _any_regex(p.r("sensitive_request"), text_lower)

    if sensitive_requested:
        score += 40
        red_flags.append("Requests sensitive information such as an OTP, password, or PIN")
    elif sensitive_mentioned:
        score += 10
        red_flags.append("Mentions sensitive information such as an OTP or verification code")

    # 4. Financial request
    financial = _any_regex(p.r("financial"), text_lower)
    if financial:
        score += 20
        red_flags.append("Contains a financial request or payment-related language")

    # 5. Banking context
    banking_context = any(term in text_lower for term in p.t("banking_term"))
    if banking_context:
        score += 5

    # 6. KYC / verification pretext
    kyc_context = _any_regex(p.r("kyc"), text_lower)
    if kyc_context:
        score += 10
        red_flags.append("Uses KYC or account-verification language")

    # 7. URL (or a website address written without http/https)
    hostnames = [_hostname(url) for url in indicators.urls]
    if bare_domains_as_links:
        hostnames += bare_link_hosts(indicators)
    has_url = bool(hostnames)
    if has_url:
        score += 5
        red_flags.append("Contains a URL")

    # Delivery scam context
    delivery_context = any(term in text_lower for term in p.t("delivery_context"))
    delivery_payment = financial
    delivery_problem = any(phrase in text_lower for phrase in p.t("delivery_problem"))

    if delivery_context and (delivery_payment or delivery_problem or has_url):
        score += 35
        red_flags.append(
            "Uses a delivery or parcel problem to request payment or direct the recipient to a link"
        )
        if delivery_payment and has_url:
            score += 15
            red_flags.append("Combines a delivery problem, payment request, and external link")

    # 8. Suspicious URL characteristics
    suspicious_url = any(
        any(hostname.endswith(tld) for tld in p.suspicious_tlds) for hostname in hostnames
    )
    if suspicious_url:
        score += 15
        red_flags.append("Uses a suspicious or unusual domain")

    # 9. Brand impersonation
    claimed_brand = None
    legitimate_domains: tuple[str, ...] = ()
    for brand in p.brands:
        if brand.pattern.search(text_lower):
            claimed_brand = brand.name
            legitimate_domains = brand.legit_domains
            break

    brand_mismatch = False
    if claimed_brand and has_url:
        for hostname in hostnames:
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

    # 10. Generic greeting
    if any(greeting in text_lower for greeting in p.t("generic_greeting")):
        score += 5
        red_flags.append("Uses a generic greeting")

    # 11. Combination rules
    if banking_context and sensitive_requested:
        score += 30
        red_flags.append("Combines banking context with a request for sensitive information")

    if banking_context and has_url:
        score += 10
        red_flags.append("Combines banking context with an external link")

    if banking_context and has_url and brand_mismatch:
        score += 15

    if kyc_context and has_url and threat_hits:
        score += 15
        red_flags.append("Combines KYC pressure, account consequences, and a link")

    # 12. Scam categories
    if sensitive_requested:
        scam_types.append("credential_phishing")

    if banking_context and (has_url or sensitive_requested or kyc_context):
        scam_types.append("banking_phishing")

    if any(word in text_lower for word in p.t("type_investment")):
        scam_types.append("investment_or_crypto")

    if any(word in text_lower for word in p.t("type_job")):
        scam_types.append("job_scam")

    if any(word in text_lower for word in p.t("type_delivery")):
        scam_types.append("delivery_scam")

    scam_types = list(dict.fromkeys(scam_types))

    # 13. Final score and risk level
    score = min(score, 100)

    if score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not red_flags:
        red_flags.append("No obvious suspicious patterns detected")

    # Pressure score: how hard the message pushes (urgency + threats), 0-100.
    urgency_score = min(100, 25 * urgency_hits + 20 * threat_hits)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "suspected_types": scam_types,
        # Added in v2 (the four keys above are unchanged from v1):
        "urgency_score": urgency_score,
        "claimed_brand": claimed_brand,
        "brand_mismatch": brand_mismatch,
        "official_domains": list(legitimate_domains) if brand_mismatch else [],
        "link_domains": [h for h in dict.fromkeys(hostnames) if h],
        "red_flag_ids": [FLAG_IDS[f] for f in red_flags if f in FLAG_IDS],
    }
