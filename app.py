import sys
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from Detection.risk_engine import analyze_email
except ImportError as exc:
    raise ImportError(
        "Could not import analyze_email from risk_engine.py. "
        "Copy your existing risk_engine.py (and its ml_detector/url_analyzer/"
        "header_analyzer dependencies) into the project root or update the "
        "import path in backend/app.py."
    ) from exc

app = Flask(__name__)
CORS(app)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}

    sender = data.get("sender", "")
    reply_to = data.get("reply_to", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    if not subject and not body:
        return jsonify({"error": "subject and body were both empty"}), 400

    try:
        result = analyze_email(sender, reply_to, subject, body)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
