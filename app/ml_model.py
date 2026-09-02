from pathlib import Path
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.linear_model import LogisticRegression

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "phishing_dataset.csv"
_model = None


def load_model():
    global _model
    if _model is None:
        df = pd.read_csv(DATA_PATH)
        required = {"subject", "message", "label"}
        missing = required - set(df.columns)
        if missing:
            raise RuntimeError(f"Dataset is missing columns: {sorted(missing)}")
        df = df.dropna(subset=["label"]).copy()
        df["subject"] = df["subject"].fillna("").astype(str)
        df["message"] = df["message"].fillna("").astype(str)
        texts = (df["subject"] + " " + df["message"]).values
        labels = df["label"].astype(str).str.lower().values

        features = FeatureUnion([
            ("word", TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                sublinear_tf=True,
                min_df=2,
                max_features=50000,
                max_df=0.98
            )),
            ("char", TfidfVectorizer(
                analyzer="char_wb",
                lowercase=True,
                ngram_range=(3, 5),
                min_df=2,
                sublinear_tf=True,
                max_features=40000
            ))
        ])

        _model = Pipeline([
            ("features", features),
            ("classifier", LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                C=2.0,
                solver="liblinear"
            ))
        ])
        _model.fit(texts, labels)
    return _model


def predict(subject: str, message: str):
    model = load_model()
    text = f"{subject} {message}".strip()
    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    phishing_probability = float(probabilities[classes.index("phishing")])
    label = "phishing" if phishing_probability >= 0.50 else "legitimate"
    return label, phishing_probability
