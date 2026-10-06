import json

from utils.security.attack_explainer import explain_attack
from utils.security.result_schema import from_json
from utils.security.risk_score import severity_cn

from .attack_knowledge import get_attack_knowledge
from .history_correlator import correlate_history
from .mitre_mapper import map_attack_chain
from .playbook import get_playbook


class AISOCAnalyzer:
    def analyze(self, traffic_record):
        detection_result = from_json(traffic_record.detection_result)
        attack_type = (
            traffic_record.attack_type
            or detection_result.get("attack_type")
            or "Normal"
        )
        knowledge = get_attack_knowledge(attack_type)
        explanation = detection_result.get("explanation") or explain_attack(attack_type).get("reasons", [])
        protocol_distribution = self._loads_json(traffic_record.protocol_distribution)
        attack_distribution = self._loads_json(traffic_record.attack_distribution)
        evidence = self._loads_json(traffic_record.evidence_json)
        chain = map_attack_chain(attack_type)
        playbook = get_playbook(attack_type)
        history = correlate_history(traffic_record, attack_type)

        risk_score = traffic_record.risk_score
        if risk_score is None:
            risk_score = detection_result.get("risk_score", 0)
        severity = traffic_record.severity or detection_result.get("severity") or "normal"

        return {
            "title": self._build_title(attack_type, knowledge),
            "attack_type": attack_type,
            "attack_name": knowledge["name"],
            "risk_score": int(risk_score or 0),
            "severity": severity,
            "severity_label": severity_cn(severity),
            "summary": knowledge["summary"],
            "cause_analysis": knowledge["cause"],
            "impact_analysis": knowledge["impact"],
            "attack_chain": chain,
            "recommendations": playbook,
            "judgement_basis": self._build_judgement_basis(
                attack_type,
                attack_distribution,
                explanation,
                chain
            ),
            "history": history,
            "evidence": {
                "file_name": traffic_record.file_name,
                "file_size": traffic_record.file_size,
                "detection_result": detection_result.get("detection_result") or traffic_record.detection_result,
                "attack_type": attack_type,
                "protocol_distribution": protocol_distribution,
                "attack_distribution": attack_distribution,
                "malicious_ratio": traffic_record.malicious_ratio,
                "confidence": traffic_record.confidence,
                "raw_evidence": evidence,
                "upload_time": str(traffic_record.upload_time) if traffic_record.upload_time else ""
            }
        }

    def _loads_json(self, text):
        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            return {}

    def _build_title(self, attack_type, knowledge):
        if attack_type == "Normal":
            return "未发现明显恶意流量"
        return f"检测到疑似 {attack_type} 安全事件"

    def _build_judgement_basis(self, attack_type, attack_distribution, explanation, chain):
        basis = []
        if attack_type == "Normal":
            basis.append("模型输出攻击类型为 Normal。")
        else:
            basis.append(f"模型输出攻击类型为 {attack_type}。")

        if attack_distribution and attack_type in attack_distribution:
            basis.append(f"攻击分布中 {attack_type} 数量为 {attack_distribution.get(attack_type)}。")
        elif attack_distribution:
            basis.append("攻击分布中存在异常流量类型，需要结合业务场景复核。")

        for reason in explanation[:2]:
            basis.append(reason)

        if chain.get("phase"):
            basis.append(f"该事件与攻击链中的“{chain['phase']}”相对应。")

        return basis
