"""Small reproducible MVP model; replace its seed corpus with a trained artifact later."""
import math

TRAINING_TEXTS = [
    "urgent verify your password immediately click this login link",
    "wire transfer required today send updated bank account details",
    "security alert confirm your account and one time password",
    "gift cards needed urgently reply with the codes",
    "meeting agenda for tomorrow and project status update",
    "thank you for your order your receipt is attached",
    "team lunch has moved to friday at noon",
    "monthly newsletter and product release notes",
]
LABELS = [1, 1, 1, 1, 0, 0, 0, 0]

def predict(text, fallback_probability):
    try:
        import torch
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        train = vectorizer.fit_transform(TRAINING_TEXTS)
        model = LogisticRegression(random_state=42, solver="liblinear").fit(train, LABELS)
        probability = float(model.predict_proba(vectorizer.transform([text]))[0, 1])
        # Temperature scaling expressed with PyTorch, ready to reuse with a saved model.
        clipped = min(max(probability, 1e-6), 1 - 1e-6)
        logit = torch.tensor(math.log(clipped / (1 - clipped)), dtype=torch.float32)
        calibrated = torch.sigmoid(logit / torch.tensor(1.15)).item()
        return {"engine": "scikit-learn TF-IDF + logistic regression; PyTorch calibration", "phishing_probability": round(calibrated, 4), "fallback": False}
    except (ImportError, RuntimeError, ValueError):
        return {"engine": "deterministic fallback (install PyTorch and scikit-learn to enable ML)", "phishing_probability": round(fallback_probability, 4), "fallback": True}

