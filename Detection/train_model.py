"""
train_model.py
Train TF-IDF + Logistic Regression phishing email classifier.
Produces:
    models/tfidf_vectorizer.pkl
    models/phishing_model.pkl
"""

import re
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATA_PATH = "Data/dataset.csv"
MODEL_DIR = "Models"
os.makedirs(MODEL_DIR, exist_ok=True)


def clean_text(text: str) -> str:
    """Lowercase, strip URLs/HTML/punctuation noise, normalize whitespace."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)          # collapse URLs to a token
    text = re.sub(r"<.*?>", " ", text)                          # strip HTML tags
    text = re.sub(r"[^a-z0-9\s]", " ", text)                    # strip punctuation
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["combined_text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
    df = df.dropna(subset=["label"])
    df["clean_text"] = df["combined_text"].apply(clean_text)
    df["label"] = df["label"].astype(int)
    return df[["clean_text", "label"]]

def train():
    print("Loading data...")
    df = load_data(DATA_PATH)
    print(f"Loaded {len(df)} rows. Label distribution:\n{df['label'].value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["clean_text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    print("Vectorizing...")
    vectorizer = TfidfVectorizer(
        max_features=5000,      
        ngram_range=(1, 2),     
        stop_words="english",
        min_df=2                
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Training Logistic Regression...")
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    preds = model.predict(X_test_vec)
    print("\nEvaluation ")
    print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
    print(classification_report(y_test, preds, target_names=["legitimate", "phishing"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, preds))

    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "vectorizer.pkl"))
    joblib.dump(model, os.path.join(MODEL_DIR, "model.pkl"))


if __name__ == "__main__":
    train()