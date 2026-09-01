"""Lazy Hugging Face RoBERTa inference for email body fraud detection."""
import os
from functools import lru_cache
from pathlib import Path

MODEL_ID = "cunxin/roberta-email-fraud-detector"
DEFAULT_LOCAL_MODEL_PATH = Path(r"C:\Users\Jahnavi\Downloads\New folder")


def _model_path():
    return Path(os.environ.get("HF_EMAIL_FRAUD_MODEL_PATH", DEFAULT_LOCAL_MODEL_PATH))


@lru_cache(maxsize=1)
def _load_model():
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    model_path = _model_path()
    required = ("config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json")
    missing = [name for name in required if not (model_path / name).is_file()]
    if missing:
        raise FileNotFoundError(f"Local model is missing: {', '.join(missing)}")

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, use_fast=True)
    model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
    model.eval()
    return tokenizer, model, torch


def predict(subject, body):
    """Return class-1 fraud probability; model downloads only on first use."""
    try:
        tokenizer, model, torch = _load_model()
        email_text = f"Subject: {subject}\n\n{body[:1800]}"
        inputs = tokenizer(email_text, return_tensors="pt", max_length=512, truncation=True, padding=True)
        with torch.inference_mode():
            probabilities = torch.softmax(model(**inputs).logits, dim=-1)
        fraud_probability = float(probabilities[0, 1].item())
        return {
            "engine": f"{MODEL_ID} (local)",
            "model_path": str(_model_path()),
            "label": "fraud" if fraud_probability >= 0.5 else "normal",
            "fraud_probability": round(fraud_probability, 4),
            "available": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": f"{MODEL_ID} (local)",
            "model_path": str(_model_path()),
            "label": "unavailable",
            "fraud_probability": None,
            "available": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
