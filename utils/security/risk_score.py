BASE_SCORE = {
    "Normal": 0,
    "PortScan": 45,
    "BruteForce": 60,
    "DDoS": 75,
    "Malware": 80,
    "DataExfiltration": 90
}

IMPORTANT_PORTS = {
    21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 6379, 8080
}


def calculate_risk_score(
    attack_type,
    malicious_ratio=0,
    repeated=False,
    threat_intel_hit=False,
    critical_asset=False,
    important_port=False,
    model_confidence=None,
    packet_count=None
):
    score = BASE_SCORE.get(attack_type, 30)

    if attack_type == "Normal":
        return 0

    ratio = malicious_ratio / 100 if malicious_ratio > 1 else malicious_ratio
    if ratio >= 0.8:
        score += 10
    elif ratio >= 0.5:
        score += 5

    if repeated:
        score += 5
    if threat_intel_hit:
        score += 10
    if critical_asset:
        score += 10
    if important_port:
        score += 5
    if model_confidence is not None and model_confidence < 0.6:
        score -= 10
    if packet_count is not None and packet_count < 10:
        score -= 10

    return max(0, min(int(round(score)), 100))


def score_to_severity(score):
    if score == 0:
        return "normal"
    if score < 40:
        return "low"
    if score < 70:
        return "medium"
    if score < 85:
        return "high"
    return "critical"


def severity_cn(severity):
    mapping = {
        "normal": "正常",
        "low": "低危",
        "medium": "中危",
        "high": "高危",
        "critical": "严重"
    }
    return mapping.get(severity, "未知")
