import json
from datetime import datetime


def build_detection_result(
    attack_type,
    detection_result,
    protocol_distribution=None,
    attack_distribution=None,
    risk_score=0,
    severity="normal",
    confidence=None,
    explanation=None,
    recommendations=None,
    threat_intel=None,
    rule_hits=None,
    evidence=None,
    topk=None,
    fusion_notes=None,
    attack_name=None,
    attack_summary=None,
    severity_label=None
):
    return {
        "attack_type": attack_type,
        "attack_name": attack_name or attack_type,
        "attack_summary": attack_summary or "",
        "detection_result": detection_result,
        "risk_score": risk_score,
        "severity": severity,
        "severity_label": severity_label or severity,
        "confidence": confidence,
        "protocol_distribution": protocol_distribution or {},
        "attack_distribution": attack_distribution or {},
        "explanation": explanation or [],
        "recommendations": recommendations or [],
        "threat_intel": threat_intel or {},
        "rule_hits": rule_hits or [],
        "evidence": evidence or {},
        "topk": topk or [],
        "fusion_notes": fusion_notes or [],
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def to_json(data):
    return json.dumps(data, ensure_ascii=False)


def from_json(text):
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        return {}
