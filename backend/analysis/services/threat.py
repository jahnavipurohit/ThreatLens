import re
from concurrent.futures import ThreadPoolExecutor
from email.utils import parseaddr
from .ml import predict
from .huggingface_fraud import predict as predict_huggingface

RULES = [
    (r"\b(urgent|immediately|act now|final warning)\b", 10, "Urgency or coercive language"),
    (r"\b(password|verify your account|login|credential|one[- ]time password|otp)\b", 18, "Credential-related request"),
    (r"\b(wire transfer|gift card|bank account|invoice payment|crypto(?:currency)?)\b", 18, "High-risk payment language"),
    (r"\b(click here|open the link|confirm now)\b", 10, "Suspicious call to action"),
]

def _domain(value):
    address = parseaddr(value)[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""

def analyze(parsed):
    metadata = parsed["metadata"]
    content = f'{metadata["subject"]}\n{parsed["body"]["text"]}'.lower()
    evidence = []
    for pattern, weight, description in RULES:
        if re.search(pattern, content, re.I):
            evidence.append({"category": "content", "description": description, "weight": weight})
    sender_domain = _domain(metadata["from"])
    for field in ("reply_to", "return_path"):
        other = _domain(metadata[field])
        if other and sender_domain and other != sender_domain:
            evidence.append({"category": "identity", "description": f'{field.replace("_", " ").title()} domain differs from From domain', "weight": 18})
    urls = parsed["indicators"]["urls"]
    if urls:
        evidence.append({"category": "ioc", "description": f"Message contains {len(urls)} URL(s)", "weight": min(12, 4 * len(urls))})
    auth_blob = " ".join(parsed["authentication_headers"]).lower()
    auth = {name: ("fail" if f"{name}=fail" in auth_blob else "pass" if f"{name}=pass" in auth_blob else "unknown") for name in ("spf", "dkim", "dmarc")}
    for name, status in auth.items():
        if status == "fail":
            evidence.append({"category": "authentication", "description": f"{name.upper()} failed", "weight": 20})
    score = min(100, sum(item["weight"] for item in evidence))
    severity = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    public_hops = [ip for hop in parsed["received"] for ip in hop["ips"] if ip["classification"] == "public"]
    origin_confidence = min(85, 25 + len(public_hops) * 15) if public_hops else 10
    fallback_probability = min(.99, score / 100)
    with ThreadPoolExecutor(max_workers=2) as executor:
        existing_future = executor.submit(predict, content, fallback_probability)
        roberta_future = executor.submit(predict_huggingface, metadata["subject"], parsed["body"]["text"])
        model_result = existing_future.result()
        roberta_result = roberta_future.result()

    existing_probability = model_result["phishing_probability"]
    if roberta_result["available"]:
        combined_confidence = round(
            (existing_probability * 0.4) + (roberta_result["fraud_probability"] * 0.6),
            4,
        )
        confidence_method = "40% existing classifier + 60% Hugging Face RoBERTa"
    else:
        combined_confidence = existing_probability
        confidence_method = "existing classifier only; RoBERTa unavailable"

    return {
        "score": score,
        "severity": severity,
        "origin_confidence": origin_confidence,
        "authentication": auth,
        "evidence": evidence,
        "model": model_result,
        "huggingface_model": roberta_result,
        "fraud_confidence": combined_confidence,
        "confidence_method": confidence_method,
    }
