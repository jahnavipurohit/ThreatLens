"""Combine independent analysis layers into one explainable final verdict."""


def calculate_final_assessment(threat, origin):
    evidence_score = float(threat.get("score", 0))
    model_score = float(threat.get("fraud_confidence", 0)) * 100
    security = origin.get("security") or {}

    infrastructure_signals = {
        "tor": 100,
        "vpn": 70,
        "proxy": 70,
        "hosting": 35,
    }
    detected = [name for name in infrastructure_signals if security.get(name)]
    infrastructure_score = max((infrastructure_signals[name] for name in detected), default=0)

    contributions = {
        "deterministic_evidence": round(evidence_score * 0.45, 2),
        "model_fraud_confidence": round(model_score * 0.45, 2),
        "infrastructure_risk": round(infrastructure_score * 0.10, 2),
    }
    overall_score = min(100, round(sum(contributions.values())))

    if overall_score >= 65:
        verdict, label = "unsafe", "Unsafe email"
    elif overall_score >= 35:
        verdict, label = "suspicious", "Suspicious email"
    else:
        verdict, label = "safe", "Safe email"

    return {
        "verdict": verdict,
        "label": label,
        "score": overall_score,
        "thresholds": {"safe": "0-34", "suspicious": "35-64", "unsafe": "65-100"},
        "weights": {"deterministic_evidence": 45, "model_fraud_confidence": 45, "infrastructure_risk": 10},
        "contributions": contributions,
        "infrastructure_signals": detected,
        "explanation": f"Final score combines evidence ({evidence_score:.0f}/100), model confidence ({model_score:.0f}/100), and infrastructure risk ({infrastructure_score}/100).",
    }
