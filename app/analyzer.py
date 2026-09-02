import re
from urllib.parse import urlparse

from .ml_model import predict
from .domain_intel import lookup_domain

URL_RE = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

SUSPICIOUS_TERMS = {
    "urgent": 8, "immediately": 7, "verify": 7, "verification": 7,
    "password": 8, "login": 6, "credential": 9, "otp": 10,
    "one time password": 10, "account suspended": 12, "account locked": 12,
    "click here": 8, "confirm your account": 10, "reset your password": 9,
    "security alert": 6, "limited time": 5, "wire transfer": 8, "gift card": 7,
    "bank account": 7, "payment failed": 6, "refund": 5, "invoice overdue": 7,
    "crypto": 5, "bitcoin": 5, "claim your prize": 9, "you have won": 9
}

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "linkedin.com", "github.com", "githubusercontent.com"
}


def extract_urls(text):
    urls = []
    for raw in URL_RE.findall(text or ""):
        url = raw.rstrip(".,);]")
        if url not in urls:
            urls.append(url)
    return urls


def _base_domain(host):
    host = host.lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def analyze_urls(urls):
    score = 0
    flags = []
    domain_reports = []
    seen_domains = set()
    for raw in urls:
        candidate = raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw
        try:
            parsed = urlparse(candidate)
            host = parsed.hostname or ""
            path = parsed.path or ""
            base = _base_domain(host)
            if parsed.scheme == "http":
                flags.append("Non-HTTPS URL detected")
                score += 8
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                flags.append("URL uses an IP address")
                score += 20
            if len(raw) > 100:
                flags.append("Unusually long URL")
                score += 7
            if host.count(".") >= 3:
                flags.append("Deeply nested subdomain structure")
                score += 7
            if "@" in raw:
                flags.append("URL contains @ symbol")
                score += 18
            if any(w in host.lower() for w in ("login", "verify", "secure", "account", "update", "wallet", "support", "signin")):
                flags.append("Security-related keyword appears in domain")
                score += 7
            if any(w in path.lower() for w in ("login", "verify", "password", "credential", "otp", "signin", "payment")):
                flags.append("Credential/payment-related URL path")
                score += 9
            if host and base not in TRUSTED_DOMAINS and any(x in host.lower() for x in ("google", "microsoft", "paypal", "apple", "amazon", "bank")):
                flags.append("Domain imitates a well-known service")
                score += 18
            if base and base not in seen_domains and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                seen_domains.add(base)
                report = await lookup_domain(base)
                domain_reports.append(report)
                if report.get("risk_added"):
                    score += report["risk_added"]
                    flags.append("Domain-age warning: " + report["summary"])
        except Exception:
            flags.append("Malformed or unusual URL detected")
            score += 12
    return min(score, 75), list(dict.fromkeys(flags)), domain_reports


def analyze_sender(sender):
    if not sender:
        return 0, []
    score = 0
    flags = []
    addresses = EMAIL_RE.findall(sender)
    if not addresses:
        return 0, []
    address = addresses[0].lower()
    domain = address.split("@", 1)[1]
    if domain.startswith(("xn--",)):
        flags.append("Sender domain uses internationalized/punycode notation")
        score += 15
    if any(x in domain for x in ("secure", "verify", "account", "support", "billing", "alert")):
        flags.append("Sender domain contains a security/account keyword")
        score += 6
    return min(score, 20), flags



def build_ai_explanation(classification, risk, reasons, domain_reports, urls):
    if classification == "PHISHING":
        opening = "This email looks like phishing. It combines signals that are commonly used to trick people into giving information, paying money, or visiting a fake website."
    elif classification == "SUSPICIOUS":
        opening = "This email has warning signs. It is safer to verify it independently before taking any action."
    else:
        opening = "No strong phishing pattern was detected in this message, but automated detection can never guarantee that an email is safe."
    actions = []
    if any("credential" in r.lower() or "password" in r.lower() or "otp" in r.lower() or "sensitive information" in r.lower() for r in reasons):
        actions.append("If you follow the request, an attacker could try to steal your password, OTP, card details, or other account information.")
    if any("domain" in r.lower() or "url" in r.lower() or "http" in r.lower() for r in reasons):
        actions.append("If you open the link, it could take you to a fake login/payment page, download harmful content, or collect information you type into it.")
    if any(d.get("status") in ("VERY_NEW", "NEW", "YOUNG") for d in domain_reports):
        actions.append("At least one linked domain is relatively new. A newly registered domain can be used for a short-lived phishing site, so avoid trusting the link just because the page looks professional.")
    if classification == "PHISHING":
        actions.append("Safer choice: do not click the link. Open the company's official app or type its official website address yourself and check for the same alert there.")
    elif classification == "SUSPICIOUS":
        actions.append("Safer choice: do not use the email link. Verify the request through a known phone number, official app, or manually typed official website.")
    else:
        actions.append("If the message asks for money, passwords, OTPs, or other sensitive information unexpectedly, verify it through a separate trusted channel.")
    return {"headline": opening, "what_could_happen": actions[:5], "plain_language": " ".join(actions[:3])}

async def analyze_message(subject, message, sender=""):
    combined = f"{subject} {message}".lower()
    ml_label, ml_probability = predict(subject, message)
    ml_score = round(ml_probability * 100)

    rule_score = 0
    reasons = []
    for term, weight in SUSPICIOUS_TERMS.items():
        if term in combined:
            rule_score += weight
            reasons.append(f"Suspicious phrase detected: '{term}'")

    urls = extract_urls(message)
    url_score, url_flags, domain_reports = await analyze_urls(urls)
    sender_score, sender_flags = analyze_sender(sender)
    reasons.extend(url_flags)
    reasons.extend(sender_flags)

    if re.search(r"\b\d{4,8}\b", combined) and any(x in combined for x in ("otp", "code", "verification")):
        reasons.append("Possible one-time verification code request")
        rule_score += 8
    if combined.count("!") >= 3:
        reasons.append("Excessive urgency/punctuation")
        rule_score += 5
    if re.search(r"\b(dear customer|dear user|valued customer|dear account holder)\b", combined):
        reasons.append("Generic recipient greeting")
        rule_score += 4
    if any(x in combined for x in ("password", "otp", "bank details", "card number", "ssn", "social security")) and any(x in combined for x in ("send", "provide", "confirm", "reply", "share")):
        reasons.append("Message requests sensitive information")
        rule_score += 12

    rule_score = min(max(rule_score, 0), 60)
    contextual_score = min(100, rule_score + url_score + sender_score)
    risk = round(min(100, ml_score * 0.72 + contextual_score * 0.55))
    if ml_label == "phishing":
        risk = max(risk, 62)
    if contextual_score >= 35:
        risk = max(risk, 55)

    if risk >= 71:
        classification = "PHISHING"
    elif risk >= 41:
        classification = "SUSPICIOUS"
    else:
        classification = "LEGITIMATE"

    confidence = round(max(55, min(99, 50 + abs(ml_probability - 0.5) * 100)))
    if not reasons:
        reasons = ["No major phishing indicators found"]

    ai_explanation = build_ai_explanation(classification, risk, reasons, domain_reports, urls)

    if classification == "PHISHING":
        recommendation = "Do not click links, open attachments, or provide credentials. Verify through an official channel and open the service manually if needed."
    elif classification == "SUSPICIOUS":
        recommendation = "Do not click links yet. Independently verify the sender and open the official website/app yourself rather than following email instructions."
    else:
        recommendation = "No strong phishing indicators were detected. Still verify unexpected requests before acting."

    return {
        "classification": classification,
        "risk_score": int(risk),
        "confidence": int(confidence),
        "reasons": list(dict.fromkeys(reasons))[:10],
        "urls": urls,
        "recommendation": recommendation,
        "ml_phishing_probability": ml_score,
        "sender": sender,
        "domain_reports": domain_reports,
        "ai_explanation": ai_explanation,
    }
