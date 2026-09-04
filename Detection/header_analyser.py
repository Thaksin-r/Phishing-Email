"""
Sender/header heuristic scoring: 
From vs Reply-To mismatch,
display-name impersonation,
 brand-domain similarity.
"""

import re
import tldextract
from rapidfuzz import fuzz

KNOWN_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "netflix.com", "instagram.com",
    "linkedin.com", "dropbox.com", "yahoo.com",
    "flipkart.com", "paytm.com", "sbi.co.in", "hdfcbank.com"
]

BRAND_NAMES = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "bank"]


def _extract_domain(email_address: str) -> str:
    match = re.search(r"@([\w\.-]+)", email_address or "")
    if not match:
        return ""
    ext = tldextract.extract(match.group(1))
    return f"{ext.domain}.{ext.suffix}"


def _extract_display_name(from_header: str) -> str:
    match = re.match(r'^\s*"?([^"<]+)"?\s*<', from_header or "")
    return match.group(1).strip() if match else ""


def header_risk_score(sender: str, reply_to: str) -> dict:
    score = 0
    flags = []

    sender_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to) if reply_to else ""
    display_name = _extract_display_name(sender).lower()

    # Check 1: From vs Reply-To domain mismatch
    if reply_domain and reply_domain != sender_domain:
        score += 30
        flags.append(f"reply_to_mismatch:{sender_domain}_vs_{reply_domain}")

    # Check 2: display name claims a brand, but sender domain isn't that brand
    for brand in BRAND_NAMES:
        if brand not in display_name:
            continue
        brand_full_domains = [d for d in KNOWN_BRANDS if brand in d]
        is_real_brand_domain = sender_domain in brand_full_domains
        if not is_real_brand_domain:
            score += 35
            if brand in sender_domain:
                flags.append(f"display_name_impersonation_domain_stuffing:{brand}")
            else:
                flags.append(f"display_name_impersonation:{brand}")
            break  # one hit is enough signal
 
    # Check 3: sender domain similarity to known brands (typosquat, not exact match)
    if sender_domain and sender_domain not in KNOWN_BRANDS:
        best = max(
                    (fuzz.ratio(sender_domain, b) / 100.0 for b in KNOWN_BRANDS),
                    default=0.0
        )
        if best > 0.75:
            score += 35
            flags.append(f"domain_typosquat:{best:.2f}")
        
    return {"score": min(score, 100), "flags": flags}