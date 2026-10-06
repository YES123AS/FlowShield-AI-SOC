ATTACK_PRIORITY = {
    "Normal": 0,
    "PortScan": 1,
    "BruteForce": 2,
    "DDoS": 3,
    "Malware": 4,
    "DataExfiltration": 5
}


def fuse_detection_result(
    model_attack_type,
    model_confidence=None,
    rule_hits=None,
    threat_intel_hits=None
):
    rule_hits = rule_hits or []
    threat_intel_hits = threat_intel_hits or []
    final_attack_type = model_attack_type
    notes = []

    rule_attack_types = [
        hit.get("attack_type")
        for hit in rule_hits
        if hit.get("attack_type")
    ]

    if model_attack_type == "Normal" and rule_attack_types:
        final_attack_type = max(
            rule_attack_types,
            key=lambda item: ATTACK_PRIORITY.get(item, 0)
        )
        notes.append("模型判断为正常，但规则引擎命中异常行为，已提升为可疑攻击事件。")

    if model_attack_type in rule_attack_types:
        notes.append("模型检测结果与规则引擎命中结果一致，检测可信度提高。")

    if rule_attack_types and model_attack_type not in rule_attack_types:
        candidates = rule_attack_types + [model_attack_type]
        final_attack_type = max(
            candidates,
            key=lambda item: ATTACK_PRIORITY.get(item, 0)
        )
        notes.append("模型结果与规则结果存在差异，系统选择风险更高的攻击类型作为最终研判。")

    if threat_intel_hits:
        notes.append("检测到 IP 命中本地威胁情报，建议提高风险等级并进行人工复核。")

    if model_confidence is not None and model_confidence < 0.6:
        notes.append("模型置信度较低，建议管理员人工复核。")

    return {
        "final_attack_type": final_attack_type,
        "fusion_notes": notes
    }
