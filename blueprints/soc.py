import json
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, redirect, render_template, url_for
from sqlalchemy import func

from decorators import login_required
from extensions import db
from models import SecurityIncidentModel
from utils.ai_soc.incident_engine import create_incident_from_traffic
from utils.ai_soc.report_generator import generate_ai_report
from utils.ai_soc.soc_agent import AISOCAnalyzer
from utils.security.risk_score import severity_cn


soc_bp = Blueprint("soc", __name__, url_prefix="/soc")


@soc_bp.route("/incidents")
@login_required
def incident_list():
    incidents = SecurityIncidentModel.query.order_by(
        SecurityIncidentModel.created_at.desc()
    ).all()
    return render_template(
        "soc/incident_list.html",
        incidents=incidents,
        severity_cn=severity_cn
    )


@soc_bp.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    incident = SecurityIncidentModel.query.get_or_404(incident_id)
    detail = _build_incident_detail_context(incident)
    return render_template(
        "soc/incident_detail.html",
        incident=incident,
        severity_cn=severity_cn,
        **detail
    )


@soc_bp.route("/incidents/<int:incident_id>/report")
@login_required
def incident_report(incident_id):
    incident = SecurityIncidentModel.query.get_or_404(incident_id)
    detail = _build_incident_detail_context(incident)
    return render_template(
        "soc/report.html",
        incident=incident,
        severity_cn=severity_cn,
        **detail
    )


@soc_bp.route("/incidents/<int:incident_id>/regenerate-ai-report", methods=["POST"])
@login_required
def regenerate_ai_report(incident_id):
    incident = SecurityIncidentModel.query.get_or_404(incident_id)
    if not incident.traffic:
        return redirect(url_for("soc.incident_detail", incident_id=incident.id))

    analyzer = AISOCAnalyzer()
    analysis = analyzer.analyze(incident.traffic)

    try:
        incident.ai_report = generate_ai_report(analysis)
        incident.llm_used = bool(incident.ai_report)
    except Exception as exc:
        incident.ai_report = f"AI 报告生成失败，已使用本地规则分析结果。错误信息：{exc}"
        incident.llm_used = False

    db.session.commit()
    return redirect(url_for("soc.incident_detail", incident_id=incident.id))


@soc_bp.route("/incidents/<int:incident_id>/resolve", methods=["POST"])
@login_required
def resolve_incident(incident_id):
    incident = SecurityIncidentModel.query.get_or_404(incident_id)
    incident.status = "resolved"
    db.session.commit()
    return redirect(url_for("soc.incident_detail", incident_id=incident.id))


@soc_bp.route("/create_from_traffic/<int:traffic_id>")
@login_required
def create_from_traffic(traffic_id):
    incident = create_incident_from_traffic(traffic_id)
    if not incident:
        return redirect(url_for("qa.index"))
    return redirect(url_for("soc.incident_detail", incident_id=incident.id))


@soc_bp.route("/dashboard")
@login_required
def dashboard():
    total = SecurityIncidentModel.query.count()
    open_count = SecurityIncidentModel.query.filter_by(status="open").count()
    resolved_count = SecurityIncidentModel.query.filter_by(status="resolved").count()
    high_count = SecurityIncidentModel.query.filter(
        SecurityIncidentModel.severity.in_(["high", "critical"])
    ).count()
    type_counts = _query_counts(SecurityIncidentModel.attack_type)
    severity_counts = _query_counts(SecurityIncidentModel.severity)
    status_counts = _query_counts(SecurityIncidentModel.status)
    trend_counts = _query_trend_counts()
    recent_incidents = SecurityIncidentModel.query.order_by(
        SecurityIncidentModel.created_at.desc()
    ).limit(8).all()

    return render_template(
        "soc/dashboard.html",
        total=total,
        open_count=open_count,
        resolved_count=resolved_count,
        high_count=high_count,
        type_counts=type_counts,
        severity_counts=severity_counts,
        status_counts=status_counts,
        trend_counts=trend_counts,
        recent_incidents=recent_incidents,
        severity_cn=severity_cn
    )


@soc_bp.route("/api/stats")
@login_required
def stats():
    total = SecurityIncidentModel.query.count()
    open_count = SecurityIncidentModel.query.filter_by(status="open").count()
    resolved_count = SecurityIncidentModel.query.filter_by(status="resolved").count()
    high_count = SecurityIncidentModel.query.filter(
        SecurityIncidentModel.severity.in_(["high", "critical"])
    ).count()
    return jsonify({
        "total": total,
        "open": open_count,
        "resolved": resolved_count,
        "high": high_count,
        "attack_types": _query_counts(SecurityIncidentModel.attack_type),
        "severity": _query_counts(SecurityIncidentModel.severity),
        "status": _query_counts(SecurityIncidentModel.status),
        "trend_30d": _query_trend_counts()
    })


def _build_incident_detail_context(incident):
    recommendations = _loads_json(incident.recommendations, [])
    attack_chain = _loads_json(incident.attack_chain, {})
    evidence = _loads_json(incident.evidence_json, {})
    judgement_basis = evidence.get("judgement_basis", [])
    history = evidence.get("history", {})

    return {
        "recommendations": recommendations,
        "attack_chain": attack_chain,
        "evidence": evidence,
        "judgement_basis": judgement_basis,
        "history": history,
        "agent_steps": _agent_steps(incident.llm_used)
    }


def _loads_json(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _query_counts(column):
    rows = db.session.query(column, func.count(SecurityIncidentModel.id)).group_by(column).all()
    return {key or "unknown": count for key, count in rows}


def _query_trend_counts():
    start_date = datetime.utcnow().date() - timedelta(days=29)
    rows = db.session.query(
        func.date(SecurityIncidentModel.created_at),
        func.count(SecurityIncidentModel.id)
    ).filter(
        SecurityIncidentModel.created_at >= start_date
    ).group_by(func.date(SecurityIncidentModel.created_at)).all()
    counts = {str(day): count for day, count in rows}
    result = []
    for offset in range(30):
        day = start_date + timedelta(days=offset)
        result.append({
            "date": day.strftime("%m-%d"),
            "count": counts.get(str(day), 0)
        })
    return result


def _agent_steps(llm_used):
    report_status = "调用 DeepSeek 生成安全事件报告" if llm_used else "DeepSeek 未启用，使用本地规则报告"
    return [
        {"name": "告警接收 Agent", "status": "完成", "description": "读取检测结果并定位原始流量记录"},
        {"name": "证据提取 Agent", "status": "完成", "description": "提取攻击类型、协议分布、攻击分布和检测证据"},
        {"name": "威胁研判 Agent", "status": "完成", "description": "计算风险等级、风险分数和历史关联"},
        {"name": "攻击链 Agent", "status": "完成", "description": "映射攻击阶段并生成攻击链分析"},
        {"name": "处置建议 Agent", "status": "完成", "description": "匹配本地响应方案和加固建议"},
        {"name": "报告生成 Agent", "status": "完成", "description": report_status}
    ]
