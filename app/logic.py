def analyze_scam(text):
    score = 0
    red_flags = []

    text_lower = text.lower()

    # Rule 1: urgency
    if any(word in text_lower for word in ["urgent", "immediately", "act now"]):
        score += 20
        red_flags.append("Creates urgency")

    # Rule 2: sensitive info
    if any(word in text_lower for word in ["otp", "password", "bank details"]):
        score += 30
        red_flags.append("Requests sensitive information")

    # Rule 3: suspicious link
    if "http" in text_lower or "www" in text_lower:
        score += 25
        red_flags.append("Contains a link")

    # Rule 4: generic greeting
    if "dear user" in text_lower or "dear customer" in text_lower:
        score += 10
        red_flags.append("Generic greeting")

    # Risk level
    if score > 70:
        level = "high"
    elif score > 40:
        level = "medium"
    else:
        level = "low"

    if not red_flags:
        red_flags.append("No obvious scam patterns detected by the rule-based checks")

    return {
        "risk_score": min(score, 100),
        "risk_level": level,
        "scam_type": "rule_based",
        "red_flags": red_flags,
        "explanation": "Rule-based analysis of common scam patterns.",
        "recommended_action": "Do not click suspicious links or share sensitive information unless you can independently verify the sender."
    }
