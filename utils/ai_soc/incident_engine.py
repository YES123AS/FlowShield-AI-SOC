import json
import uuid
from datetime import datetime

from extensions import db
from models import SecurityIncidentModel, TrafficModel

from .report_generator import generate_ai_report
from .soc_agent import AISOCAnalyzer


def create_incident_from_traffic(traffic_id, use_llm=True):
    traffic = TrafficModel.query.get(traffic_id)
    if not traffic:
        return None

    existing = SecurityIncidentModel.query.filter_by(traffic_id=traffic.id).first()
    if existing:
        return existing

    analyzer = AISOCAnalyzer()
    analysis = analyzer.analyze(traffic)

    ai_report = ""
    llm_used = False
    if use_llm:
        try:
            ai_report = generate_ai_report(analysis)
            llm_used = bool(ai_report)
        except Exception as exc:
            ai_report = f"AI 报告生成失败，已使用本地规则分析结果。错误信息：{exc}"
            llm_used = False

    evidence = dict(analysis["evidence"])
    evidence["judgement_basis"] = analysis["judgement_basis"]
    evidence["history"] = analysis["history"]

    incident = SecurityIncidentModel(
        traffic_id=traffic.id,
        incident_no=generate_incident_no(),
        title=analysis["title"],
        attack_type=analysis["attack_type"],
        severity=analysis["severity"],
        risk_score=analysis["risk_score"],
        status="open",
        summary=analysis["summary"],
        cause_analysis=analysis["cause_analysis"],
        impact_analysis=analysis["impact_analysis"],
        attack_chain=json.dumps(analysis["attack_chain"], ensure_ascii=False),
        recommendations=json.dumps(analysis["recommendations"], ensure_ascii=False),
        evidence_json=json.dumps(evidence, ensure_ascii=False),
        ai_report=ai_report,
        llm_used=llm_used
    )

    db.session.add(incident)
    db.session.commit()
    return incident


def generate_incident_no():
    date_str = datetime.now().strftime("%Y%m%d")
    short_id = uuid.uuid4().hex[:8].upper()
    return f"INC-{date_str}-{short_id}"
