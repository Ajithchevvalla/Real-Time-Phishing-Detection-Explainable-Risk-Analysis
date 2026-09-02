import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

# RDAP is used only for registration metadata. We never request the email URL itself.
RDAP_BOOTSTRAP = "https://rdap.org/domain/{}"
TLD_RDAP = {"com": "https://rdap.verisign.com/com/v1/domain/{}", "net": "https://rdap.verisign.com/net/v1/domain/{}"}


def root_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _creation_date(data):
    for ev in data.get("events", []) if isinstance(data, dict) else []:
        if ev.get("eventAction") in ("registration", "registered") and ev.get("eventDate"):
            return ev["eventDate"]
    return None


def _age_days(created):
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def explain_domain(domain: str, age_days, registration_available=True):
    if not registration_available:
        return {
            "status": "UNKNOWN",
            "risk_added": 0,
            "summary": "The domain's registration age could not be verified right now.",
            "simple_explanation": "We could not confirm when this domain was created, so domain age is not being treated as proof that it is safe or dangerous.",
        }
    if age_days is None:
        return {
            "status": "UNKNOWN", "risk_added": 0,
            "summary": "Registration date was not available.",
            "simple_explanation": "The registry did not provide a usable creation date. Other phishing signals should be considered instead.",
        }
    if age_days < 30:
        return {
            "status": "VERY_NEW", "risk_added": 22,
            "summary": f"Domain is very new ({age_days} days old).",
            "simple_explanation": "A very new domain deserves extra caution. Attackers can create a fresh website and use it briefly for phishing. A new domain is not automatically malicious, but combined with an urgent email or login request it is a strong warning sign.",
        }
    if age_days < 90:
        return {
            "status": "NEW", "risk_added": 15,
            "summary": f"Domain is relatively new ({age_days} days old).",
            "simple_explanation": "This domain was registered recently. That does not prove it is a scam, but it increases caution when the email also asks you to log in, pay, verify, or share sensitive information.",
        }
    if age_days < 365:
        return {
            "status": "YOUNG", "risk_added": 7,
            "summary": f"Domain is less than one year old ({age_days} days old).",
            "simple_explanation": "The domain is young. Treat unexpected requests carefully, especially if the email uses urgency or asks for credentials or payment.",
        }
    return {
        "status": "ESTABLISHED", "risk_added": 0,
        "summary": f"Domain has been registered for about {age_days // 365} year(s).",
        "simple_explanation": "The domain is not newly registered. Domain age alone cannot prove an email is safe, so the other message and URL signals still matter.",
    }


async def lookup_domain(domain: str):
    domain = root_domain(domain)
    if not domain or "." not in domain:
        return {"domain": domain, "available": False, **explain_domain(domain, None, False)}
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers={"Accept": "application/rdap+json, application/json"}) as client:
            tld = domain.rsplit(".", 1)[-1]
            endpoint = TLD_RDAP.get(tld, RDAP_BOOTSTRAP)
            r = await client.get(endpoint.format(domain))
            if r.status_code != 200:
                return {"domain": domain, "available": False, **explain_domain(domain, None, False)}
            data = r.json()
        created = _creation_date(data)
        age = _age_days(created)
        info = explain_domain(domain, age, True)
        return {"domain": domain, "available": True, "created": created, "age_days": age, **info}
    except Exception:
        return {"domain": domain, "available": False, **explain_domain(domain, None, False)}
