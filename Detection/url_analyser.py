"""
detection/url_analyzer.py
Heuristic URL risk scoring. No redirect-chasing, no live browsing —
keeps it fast/safe per project scope.
"""

import re
import socket
from urllib.parse import urlparse
from rapidfuzz import fuzz

import tldextract
import whois

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "password", "account", "secure",
    "update", "banking", "confirm", "signin", "security"
]

KNOWN_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "netflix.com", "instagram.com",
    "linkedin.com", "dropbox.com", "yahoo.com",
    "flipkart.com", "paytm.com", "sbi.co.in", "hdfcbank.com"
]

BRAND_NAMES = [d.split(".")[0] for d in KNOWN_BRANDS]

def _brand_stuffing_check(domain: str) -> str | None:
    """Catches brand name stuffed into a longer fake domain, e.g.
    'fake-paypal-login-verify.xyz' — Levenshtein ratio misses this."""
    for brand in BRAND_NAMES:
        if brand in domain and domain not in KNOWN_BRANDS:
            brand_real_domains = [d for d in KNOWN_BRANDS if brand in d]
            if domain not in brand_real_domains:
                return brand
    return None

def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text)


def _is_ip_hostname(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except (socket.error, TypeError):
        return False


def _domain_similarity(domain: str) -> float:
    #Cheap Levenshtein-ratio check against known brands.
    #Returns highest similarity found (0-1). High similarity to a brand

    best = 0.0
    for brand in KNOWN_BRANDS:
        if domain == brand:
            continue  # exact match to real brand = not typosquatting
        score = fuzz.ratio(domain, brand) / 100.0
        best = max(best, score)
    return best


def _domain_age_days(domain: str):
    """Returns age in days, or None if lookup fails (don't penalize on lookup failure)."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        from datetime import datetime
        return (datetime.now() - creation).days
    except Exception:
        return None  # WHOIS can fail/timeout often — fail open, don't penalize


def analyze_url(url: str) -> dict:
    score = 0
    flags = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"

    # Check 1: HTTP not HTTPS
    if parsed.scheme == "http":
        score += 15
        flags.append("insecure_http")

    # Check 2: raw IP as hostname
    if _is_ip_hostname(hostname):
        score += 30
        flags.append("ip_address_url")

    # Check 3: suspicious keywords in URL
    lower_url = url.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    if hits:
        score += min(len(hits) * 7, 20)  # cap contribution, avoid keyword-stuffing skew
        flags.append(f"suspicious_keywords:{','.join(hits)}")

    # Check 4: subdomain depth (e.g. paypal.login.verify.fake.xyz)
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
    if len(subdomain_parts) >= 3:
        score += 15
        flags.append("deep_subdomain")

    # Check 5: brand typosquatting similarity
    similarity = _domain_similarity(registered_domain)
    if similarity > 0.75:  # close-but-not-exact match to a known brand
        score += 25
        flags.append(f"brand_typosquat:{similarity:.2f}")

    stuffed_brand = _brand_stuffing_check(registered_domain)
    if stuffed_brand:
        score += 25
        flags.append(f"brand_domain_stuffing:{stuffed_brand}")
    # Check 6: domain age (best-effort, WHOIS is slow/flaky — call sparingly)
    age = _domain_age_days(registered_domain)
    if age is not None and age < 30:
        score += 20
        flags.append(f"new_domain:{age}days")

    return {"url": url, "score": min(score, 100), "flags": flags}


def url_risk_score(urls: list) -> dict:
    if not urls:
        return {"score": 0, "details": []}

    results = [analyze_url(u) for u in urls]
    worst = max(results, key=lambda r: r["score"])
    return {"score": worst["score"], "details": results}