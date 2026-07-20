import argparse
import re
from pathlib import Path

import joblib
import nltk
import numpy as np
import pandas as pd
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET = BASE_DIR / "phishing_emails_dataset.csv"
DEFAULT_MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = DEFAULT_MODEL_DIR / "phishing_model.pkl"
VECTORIZER_PATH = DEFAULT_MODEL_DIR / "tfidf_vectorizer.pkl"
STOPWORDS_PATH = Path(nltk.data.path[0]) / "corpora" / "stopwords"


def ensure_stopwords() -> set[str]:
    if not STOPWORDS_PATH.exists():
        nltk.download("stopwords", quiet=True)
    return set(stopwords.words("english"))


STOP_WORDS = ensure_stopwords()


def clean_text(text: str) -> str:
    text = re.sub(r"<.*?>", "", str(text))
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"[^a-zA-Z]", " ", text)
    text = text.lower()
    return " ".join(word for word in text.split() if word not in STOP_WORDS)


def load_dataset(path: Path) -> pd.DataFrame:
    data = pd.read_csv(path)
    data.columns = data.columns.str.strip()

    missing = {"text", "label"} - set(data.columns)
    if missing:
        raise ValueError(f"Missing required dataset columns: {', '.join(sorted(missing))}")

    data = data[["text", "label"]].dropna()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)
    return data


def train_model(dataset_path: Path, model_dir: Path) -> None:
    data = load_dataset(dataset_path)
    data["clean_text"] = data["text"].apply(clean_text)

    vectorizer = TfidfVectorizer(max_features=7000, ngram_range=(1, 2))
    x = vectorizer.fit_transform(data["clean_text"])
    y = data["label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / MODEL_PATH.name)
    joblib.dump(vectorizer, model_dir / VECTORIZER_PATH.name)

    print(classification_report(y_test, y_pred))
    print_top_terms(model, vectorizer)
    print(f"Saved model to: {model_dir / MODEL_PATH.name}")
    print(f"Saved vectorizer to: {model_dir / VECTORIZER_PATH.name}")


def load_model(model_dir: Path) -> tuple[LogisticRegression, TfidfVectorizer]:
    model_path = model_dir / MODEL_PATH.name
    vectorizer_path = model_dir / VECTORIZER_PATH.name

    if not model_path.exists() or not vectorizer_path.exists():
        raise FileNotFoundError("Model files not found. Run train first.")

    return joblib.load(model_path), joblib.load(vectorizer_path)


def predict_text(text: str, model: LogisticRegression, vectorizer: TfidfVectorizer) -> dict[str, object]:
    clean = clean_text(text)
    vector = vectorizer.transform([clean])
    probability = float(model.predict_proba(vector)[0][1])
    prediction = int(probability >= 0.5)

    return {
        "text": text,
        "phishing_probability": round(probability, 4),
        "prediction": "phishing" if prediction else "legitimate",
        "risk_level": risk_level(probability),
        "top_suspicious_terms": ", ".join(top_suspicious_terms(clean, model, vectorizer)),
    }


def predict_file(path: Path, model: LogisticRegression, vectorizer: TfidfVectorizer) -> dict[str, object]:
    return predict_text(path.read_text(encoding="utf-8"), model, vectorizer)


def predict_batch(input_path: Path, output_path: Path, model: LogisticRegression, vectorizer: TfidfVectorizer) -> None:
    data = pd.read_csv(input_path)
    data.columns = data.columns.str.strip()
    if "text" not in data.columns:
        raise ValueError("Batch input CSV must contain a text column.")

    predictions = [predict_text(text, model, vectorizer) for text in data["text"].fillna("")]
    result = pd.concat([data.reset_index(drop=True), pd.DataFrame(predictions).drop(columns=["text"])], axis=1)
    result.to_csv(output_path, index=False)
    print(f"Saved results to: {output_path}")
    print(result[["phishing_probability", "prediction", "risk_level", "top_suspicious_terms"]].head(20))


def risk_level(probability: float) -> str:
    if probability >= 0.8:
        return "high"
    if probability >= 0.5:
        return "medium"
    return "low"


def top_suspicious_terms(clean: str, model: LogisticRegression, vectorizer: TfidfVectorizer, limit: int = 5) -> list[str]:
    feature_names = vectorizer.get_feature_names_out()
    vocabulary = vectorizer.vocabulary_
    coefs = model.coef_[0]

    terms = []
    for term in set(clean.split()):
        index = vocabulary.get(term)
        if index is not None and coefs[index] > 0:
            terms.append((term, coefs[index]))

    return [term for term, _ in sorted(terms, key=lambda item: item[1], reverse=True)[:limit]]


def print_top_terms(model: LogisticRegression, vectorizer: TfidfVectorizer) -> None:
    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]
    top_phishing = np.argsort(coefs)[-10:][::-1]
    top_legitimate = np.argsort(coefs)[:10]

    print("Top phishing terms:", [feature_names[i] for i in top_phishing])
    print("Top legitimate terms:", [feature_names[i] for i in top_legitimate])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train and run a phishing email detector.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train and save the phishing model.")
    train_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    train_parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)

    predict_parser = subparsers.add_parser("predict", help="Predict one email from text or file.")
    predict_parser.add_argument("--text")
    predict_parser.add_argument("--file", type=Path)
    predict_parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)

    batch_parser = subparsers.add_parser("batch", help="Predict phishing risk for a CSV with a text column.")
    batch_parser.add_argument("--input", type=Path, required=True)
    batch_parser.add_argument("--output", type=Path, default=BASE_DIR / "phishing_results.csv")
    batch_parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.command == "train":
        train_model(args.dataset, args.model_dir)
        return

    model, vectorizer = load_model(args.model_dir)

    if args.command == "predict":
        if bool(args.text) == bool(args.file):
            raise ValueError("Use exactly one of --text or --file.")
        result = predict_text(args.text, model, vectorizer) if args.text else predict_file(args.file, model, vectorizer)
        print(pd.DataFrame([result]).drop(columns=["text"]).to_string(index=False))
        return

    if args.command == "batch":
        predict_batch(args.input, args.output, model, vectorizer)


if __name__ == "__main__":
    main()
