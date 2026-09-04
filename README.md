# 🛡️ Phishing Email Catcher

AI-powered phishing email detection: TF-IDF + Logistic Regression for content
classification, combined with URL and sender/header heuristics, fused into a
single weighted risk score. Includes a Flask backend and a Chrome extension
frontend.

Built as a resume/portfolio project — prioritizes being fast to build,
explainable in an interview, and free of GPU/paid-API dependencies over
maximum sophistication.

---

## Architecture

```
                         📧 EMAIL INPUT
                                │
                       (from the extension /
                        any HTTP client)
                                │
                                ▼
                        Flask  /analyze
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
         ▼                      ▼                      ▼
   HEADER ANALYSIS          URL ANALYSIS         ML ANALYSIS
   Sender / Reply-To        Heuristics only —    TF-IDF + Logistic
   domain mismatch,         no live browsing,     Regression, with
   brand impersonation,     no redirect-chasing   per-word
   typosquat                                      explainability
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                ▼
                        RISK FUSION ENGINE
                   AI 50% · URL 30% · Header 20%
                                │
                                ▼
              SAFE / LOW RISK / SUSPICIOUS / PHISHING
```

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| ML | scikit-learn TF-IDF + Logistic Regression | No GPU needed, fast to train, `.coef_`-based explainability is easy to defend in an interview — chosen over RoBERTa+PEFT for exactly this reason |
| Backend | Flask + flask-cors | Lightweight API for the extension to call |
| Frontend | Chrome extension (`extension/`) | Popup checks backend `/health`, background/content scripts handle in-page detection |
| URL/domain heuristics | `tldextract`, `python-whois`, `rapidfuzz` | Free, local, no API key required |
| Dataset | [`naserabdullahalam/phishing-email-dataset`](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) (Kaggle) | ~39k labeled emails (this project's copy), combining Enron/Ling/CEAS/Nazario/Nigerian Fraud/SpamAssassin sources |

**Deliberately NOT used:** RoBERTa/PEFT/transformers (GPU + explainability
cost too high for the timeline), CleanTalk API (external paid/rate-limited
dependency), live URL-visiting or redirect-chasing (safety/speed).

---

## Project structure

```
Phishing Email/
├── app.py                     # Flask API entry point (POST /analyze, GET /health)
├── requirements.txt
├── .gitignore
├── .env                       # NOT committed — create locally, see Setup below
│
├── Data/
│   └── dataset.csv            # Kaggle phishing email dataset
│
├── Detection/
│   ├── train_model.py         # Train + save the TF-IDF/LogReg model
│   ├── ML_Detector.py         # score_email() — inference + explainability
│   ├── url_analyser.py        # URL heuristic scoring
│   ├── header_analyser.py     # Sender/header heuristic scoring
│   └── risk_engine.py         # analyze_email() — fuses all three into one verdict
│
├── Models/
│   ├── model.pkl              # Trained Logistic Regression model
│   └── vectorizer.pkl         # Fitted TF-IDF vectorizer
│
├── Tests/
│   ├── conftest.py
│   ├── test_header_analyser.py
│   ├── test_url_analyser.py
│   ├── test_ml_detector.py
│   └── test_risk_engine.py
│
└── extension/
    ├── manifest.json
    ├── background.js
    ├── content.js
    ├── popup.html / popup.js / styles.css
    └── icons/
```

---

## Setup

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Create `.env`** at the project root (never commit this):
   ```
   FLASK_ENV=development
   ```
   *(Add any Gmail OAuth / DB credentials here if/when those are integrated —
   see Known Limitations below.)*

3. **Train the model** (from the project root):
   ```bash
   python Detection/train_model.py
   ```
   This reads `Data/dataset.csv`, trains, prints accuracy/confusion matrix,
   and writes `Models/model.pkl` + `Models/vectorizer.pkl`. Pretrained
   copies are already included in this repo, so this step is optional
   unless you want to retrain on new data.

   Last recorded run: **99.45% test accuracy** (7,831 held-out emails,
   39,154 total rows, label split ~21.8k phishing / ~17.3k legitimate).

4. **Run the backend**
   ```bash
   python app.py
   ```
   Serves on `http://127.0.0.1:5000`. Check `GET /health` returns
   `{"status": "ok"}`.

5. **Load the Chrome extension**
   - Go to `chrome://extensions`, enable Developer Mode, "Load unpacked",
     select the `extension/` folder.
   - The popup checks the backend's `/health` endpoint on open.

---

## Running tests

```bash
pip install pytest   # already in requirements.txt
pytest Tests/ -v
```

Test files require `Models/model.pkl` and `Models/vectorizer.pkl` to exist
(run `train_model.py` first if you deleted them). URL/header tests
monkeypatch the WHOIS domain-age lookup so the suite doesn't depend on
network access — only `test_domain_age_new_domain_flagged` exercises that
path, and it's also mocked, not a real network call.

**These tests have been written but not yet executed in this environment**
(no network access here to install `rapidfuzz`/`tldextract`/`python-whois`
to actually run them) — run them locally and report back what fails.

---

## API

```
POST /analyze
Content-Type: application/json

{
  "sender": "PayPal Security <security@fake-paypal-login.xyz>",
  "reply_to": "attacker@gmail.com",
  "subject": "Urgent: Verify Your Account",
  "body": "Your account will be suspended within 24 hours. Click here: http://fake-paypal-login-verify.xyz/login"
}
```

Response:
```json
{
  "final_score": 71.2,
  "label": "PHISHING",
  "breakdown": {"ai_score": 82.4, "url_score": 79.0, "header_score": 65.0},
  "reasons": [
    {"word": "suspended", "source": "ml"},
    {"word": "brand_domain_stuffing:paypal", "source": "url"},
    {"word": "reply_to_mismatch:fake-paypal-login.xyz_vs_gmail.com", "source": "header"}
  ],
  "urls_found": ["http://fake-paypal-login-verify.xyz/login"]
}
```

Risk tiers: `0–10 SAFE · 11–30 LOW RISK · 31–60 SUSPICIOUS · 61–100 PHISHING`

---

## Known limitations / not yet built

- **WHOIS domain-age lookups are live network calls** — slow, can time out,
  fail open (no penalty) on error. Fine for single-email interactive use;
  would need caching for batch scanning.
- **No database layer yet.** Dual Oracle (local) / SQLite (public demo)
  storage was planned but not implemented in this codebase — results are
  not currently persisted anywhere.
- **No Gmail OAuth input path in this codebase** — the extension reads
  page content directly; a "fetch from Gmail" input source was discussed
  but isn't wired up here.
- **`KNOWN_BRANDS` / `SUSPICIOUS_KEYWORDS` are small hardcoded lists** —
  fine for a demo, easy to extend, but not exhaustive.

---

## Recent bug fixes (this pass)

| Bug | Fix |
|---|---|
| `train_model.py` / `ML_Detector.py` used cwd-relative paths, broke if run from any directory but project root | Anchored all paths to `Path(__file__).resolve().parent` |
| `ML_Detector.py` / `risk_engine.py` imports failed when run as a direct script instead of `-m` | Added project root to `sys.path` + try/except import fallback |
| `app.py` inserted `.parent.parent` into `sys.path` (one level too high) | Fixed to `.parent`; previously only "worked" by accident |
| `app.py` swallowed real import errors (e.g. missing `rapidfuzz`) behind a misleading "copy your files" message | Now surfaces the original exception message |
| `.gitignore` excluded the actual source files (`ML_Detector.py`, `train_model.py`) instead of secrets/binaries | Rewritten to ignore `.env`/`__pycache__`/model binaries instead |
| `url_analyser.py`'s brand-typosquat check missed brand names stuffed into longer fake domains (e.g. `fake-paypal-login-verify.xyz`) — same bug already fixed in `header_analyser.py` but not ported over | Added matching `_brand_stuffing_check()` to `url_analyser.py` |
| No `requirements.txt` existed | Added, covering all imports actually used across the codebase |
