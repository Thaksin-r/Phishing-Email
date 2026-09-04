"""
detection/risk_engine.py
Ties ml_detector + url_analyzer + header_analyzer into one final verdict.
This is the main entry point the Streamlit app / API layer should call.
"""

from Detection.ML_Detector import score_email
from Detection.url_analyser import extract_urls, url_risk_score
from Detection.header_analyser import header_risk_score

WEIGHTS = {"ai": 0.50, "url": 0.30, "header": 0.20}


def classify(final_score: float) -> str:
    if final_score <= 30:
        return "SAFE"
    elif final_score <= 60:
        return "SUSPICIOUS"
    else:
        return "PHISHING"


def analyze_email(sender: str, reply_to: str, subject: str, body: str) -> dict:
    # 1. AI/ML score + explainability
    ai_result = score_email(subject, body)

    # 2. URL heuristics
    urls = extract_urls(body)
    url_result = url_risk_score(urls)

    # 3. Header/sender heuristics
    header_result = header_risk_score(sender, reply_to)

    # 4. Fusion
    final = (
        ai_result["ai_score"] * WEIGHTS["ai"]
        + url_result["score"] * WEIGHTS["url"]
        + header_result["score"] * WEIGHTS["header"]
    )
    final = round(final, 2)
    label = classify(final)

    # Merge flags into human-readable reasons for dashboard display
    reasons = [r["word"] for r in ai_result["reasons"]]
    if url_result["details"]:
        worst_url = max(
                        url_result["details"],
                        key=lambda x: x["score"]
                    )
        reasons += worst_url["flags"]
    reasons += header_result["flags"]

    return {
        "final_score": final,
        "label": label,
        "breakdown": {
            "ai_score": ai_result["ai_score"],
            "url_score": url_result["score"],
            "header_score": header_result["score"],
        },
        "reasons": reasons,
        "urls_found": urls,
    }


if __name__ == "__main__":
    result = analyze_email(
        sender="PayPal Security <security@fake-paypal-login.xyz>",
        reply_to="attacker@gmail.com",
        subject="Urgent: Verify Your Account",
        body=(
            "Your account will be suspended within 24 hours. "
            "Click here to verify: http://fake-paypal-login-verify.xyz/login"
        ),
    )
    import json
    print(json.dumps(result, indent=2))