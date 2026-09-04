"""
detection/ml_detector.py
Load trained TF-IDF + LogisticRegression model, score new emails,
and explain which words drove the prediction.
"""

import joblib
from train_model import clean_text

MODEL_DIR = "Models"

_vectorizer = joblib.load(f"{MODEL_DIR}/vectorizer.pkl")
_model = joblib.load(f"{MODEL_DIR}/model.pkl")


def score_email(subject: str, body: str, top_n: int = 5) -> dict:
    raw_text = f"{subject} {body}"
    text = clean_text(raw_text)

    vec = _vectorizer.transform([text])
    prob_phishing = _model.predict_proba(vec)[0][1]
    ai_score = round(prob_phishing * 100, 2)

    reasons = _explain(vec, top_n=top_n)

    return {
        "ai_score": ai_score,
        "label": "phishing" if prob_phishing >= 0.5 else "legitimate",
        "reasons": reasons,
    }



def _explain(vec, top_n: int = 5) -> list:
    """
    Contribution of each present word = tfidf_value * logreg_coefficient.
    Positive contribution => pushed toward phishing class.
    Only returns words that were actually present in the email (nonzero TF-IDF).
    """
    feature_names = _vectorizer.get_feature_names_out()
    coefs = _model.coef_[0]

    vec_dense = vec.toarray()[0]
    nonzero_idx = vec_dense.nonzero()[0]

    contributions = [
        (feature_names[i], float(vec_dense[i] * coefs[i]))
        for i in nonzero_idx
    ]

    # Sort by contribution descending — most "phishing-pushing" words first
    contributions.sort(key=lambda x: x[1], reverse=True)

    top_positive = [
        {"word": w, "weight": round(wt, 4)}
        for w, wt in contributions[:top_n]
        if wt > 0
    ]
    return top_positive


if __name__ == "__main__":
    test_subject = "Urgent: Verify Your Account"
    test_body = "Your account will be suspended within 24 hours. Click below to verify your password."
    result = score_email(test_subject, test_body)
    print(result)