from flask import Blueprint, render_template, jsonify
from models import TrafficModel
from datetime import datetime, timedelta
import json
import ast

analysis_bp = Blueprint('analysis', __name__, url_prefix='/analysis')


@analysis_bp.route('/dashboard')
def dashboard():
    """数据分析仪表盘路由"""
    return render_template('analysis/dashboard.html')


@analysis_bp.route('/api/traffic_stats')
def traffic_stats():
    """获取流量统计数据API"""
    # 获取最近30天的数据
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    # 查询数据库获取基础数据
    traffic_data = TrafficModel.query.filter(
        TrafficModel.upload_time.between(start_date, end_date)
    ).all()

    # 处理数据为可视化格式
    stats = {
        'time_series': process_time_series_data(traffic_data),
        'threat_types': process_threat_type_data(traffic_data),
        'file_size_distribution': process_file_size_data(traffic_data),
        'top_threats': process_top_threats_data(traffic_data),
        'severity_distribution': process_severity_distribution(traffic_data),
        'risk_score_trend': process_risk_score_trend(traffic_data),
        'high_risk_trend': process_high_risk_trend(traffic_data),
        'threat_intel_hits': process_threat_intel_hits(traffic_data),
        'rule_hit_ranking': process_rule_hit_ranking(traffic_data)
    }

    return jsonify(stats)


def process_time_series_data(data):
    """处理时间序列数据"""
    daily_counts = {}
    for record in data:
        date = record.upload_time.strftime('%Y-%m-%d')
        daily_counts[date] = daily_counts.get(date, 0) + 1

    # 填充完整30天的数据
    dates = [(datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
             for i in range(29, -1, -1)]
    counts = [daily_counts.get(date, 0) for date in dates]

    return {'dates': dates, 'counts': counts}


def process_threat_type_data(data):
    threat_types = {}
    for record in data:
        attack_distribution = _load_json_field(record.attack_distribution)
        if attack_distribution:
            for threat_type, count in attack_distribution.items():
                if threat_type == 'Normal':
                    continue
                threat_types[threat_type] = threat_types.get(threat_type, 0) + int(count)
            continue

        if record.attack_type and record.attack_type != 'Normal':
            threat_types[record.attack_type] = threat_types.get(record.attack_type, 0) + 1
    return {'types': list(threat_types.keys()), 'counts': list(threat_types.values())}


def process_file_size_data(data):
    """按文件大小区间统计数量，单位：MB"""
    ranges = ['0-1MB', '1-5MB', '5-10MB', '10MB+']
    counts = [0, 0, 0, 0]
    for record in data:
        if record.file_size is None:
            continue
        size_mb = record.file_size / (1024 * 1024)
        if size_mb < 1:
            counts[0] += 1
        elif size_mb < 5:
            counts[1] += 1
        elif size_mb < 10:
            counts[2] += 1
        else:
            counts[3] += 1
    return {'ranges': ranges, 'counts': counts}


def process_top_threats_data(data):
    threats = {}
    for record in data:
        attack_distribution = _load_json_field(record.attack_distribution)
        if attack_distribution:
            for name, count in attack_distribution.items():
                if name == 'Normal':
                    continue
                threats[name] = threats.get(name, 0) + int(count)
            continue

        if record.attack_type and record.attack_type != 'Normal':
            threats[record.attack_type] = threats.get(record.attack_type, 0) + 1

    # 取前10个最常见的威胁
    sorted_threats = sorted(threats.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        'names': [t[0] for t in sorted_threats],
        'counts': [t[1] for t in sorted_threats]
    }


def process_severity_distribution(data):
    labels = ["normal", "low", "medium", "high", "critical"]
    counts = {label: 0 for label in labels}
    for record in data:
        severity = record.severity or _load_detection_result(record).get("severity") or "normal"
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "types": list(counts.keys()),
        "counts": list(counts.values())
    }


def process_risk_score_trend(data):
    daily = {}
    for record in data:
        date = record.upload_time.strftime('%Y-%m-%d')
        risk_score = record.risk_score
        if risk_score is None:
            risk_score = _load_detection_result(record).get("risk_score", 0)
        daily.setdefault(date, []).append(float(risk_score or 0))

    dates = [(datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
             for i in range(29, -1, -1)]
    scores = []
    for date in dates:
        values = daily.get(date, [])
        scores.append(round(sum(values) / len(values), 2) if values else 0)
    return {"dates": dates, "scores": scores}


def process_high_risk_trend(data):
    daily = {}
    for record in data:
        date = record.upload_time.strftime('%Y-%m-%d')
        risk_score = record.risk_score
        if risk_score is None:
            risk_score = _load_detection_result(record).get("risk_score", 0)
        if float(risk_score or 0) >= 70:
            daily[date] = daily.get(date, 0) + 1

    dates = [(datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
             for i in range(29, -1, -1)]
    return {"dates": dates, "counts": [daily.get(date, 0) for date in dates]}


def process_threat_intel_hits(data):
    total = 0
    for record in data:
        detection_result = _load_detection_result(record)
        hits = detection_result.get("threat_intel", {}).get("hits", [])
        total += len(hits)
    return {"count": total}


def process_rule_hit_ranking(data):
    rule_counts = {}
    for record in data:
        detection_result = _load_detection_result(record)
        for rule in detection_result.get("rule_hits", []):
            name = rule.get("name") or rule.get("rule_id") or "Unknown"
            rule_counts[name] = rule_counts.get(name, 0) + 1

    ranking = sorted(rule_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    return {
        "names": [item[0] for item in ranking],
        "counts": [item[1] for item in ranking]
    }


def _load_json_field(value):
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        try:
            parsed = ast.literal_eval(value)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, SyntaxError):
            return {}


def _load_detection_result(record):
    return _load_json_field(record.detection_result)
