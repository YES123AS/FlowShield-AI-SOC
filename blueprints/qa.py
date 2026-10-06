import logging
import os
import subprocess
import time
from datetime import datetime

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for
from scapy.all import sniff, wrpcap
from sqlalchemy import func

from .forms import QuestionForm, AnswerForm
from models import QuestionModel, AnswerModel, TrafficModel, LogModel, SecurityIncidentModel
from extensions import db
from decorators import login_required
from utils.predict import detector_status, predict
from utils.security.attack_explainer import explain_attack
from utils.security.detection_fusion import fuse_detection_result
from utils.security.response_playbook import get_recommendations
from utils.security.result_schema import build_detection_result, to_json
from utils.security.risk_score import IMPORTANT_PORTS, calculate_risk_score, score_to_severity, severity_cn
from utils.security.rule_engine import run_rule_engine
from utils.security.threat_intel import check_ip_reputation
from utils.ai_soc.incident_engine import create_incident_from_traffic
from utils.security.upload_security import build_safe_upload_path, validate_pcap_upload

bp = Blueprint("qa", __name__, url_prefix="/")


@bp.route("/api/detector/status", methods=["GET"])
@login_required
def get_detector_status():
    try:
        return jsonify({"success": True, **detector_status(load_model=True)})
    except Exception as exc:
        logging.exception("检测模型自检失败")
        return jsonify({"success": False, "error": str(exc)}), 503

# http://127.0.0.1:5000
@bp.route("/")
@login_required
def index():
    traffics = TrafficModel.query.order_by(TrafficModel.upload_time.desc()).all()
    today = datetime.utcnow().date()
    today_detection_count = TrafficModel.query.filter(func.date(TrafficModel.upload_time) == today).count()
    today_malicious_count = TrafficModel.query.filter(
        func.date(TrafficModel.upload_time) == today,
        TrafficModel.attack_type != "Normal"
    ).count()
    high_event_count = SecurityIncidentModel.query.filter(
        SecurityIncidentModel.severity.in_(["high", "critical"])
    ).count()
    open_event_count = SecurityIncidentModel.query.filter_by(status="open").count()
    common_attack = db.session.query(
        TrafficModel.attack_type,
        func.count(TrafficModel.id)
    ).filter(
        TrafficModel.attack_type.isnot(None),
        TrafficModel.attack_type != "Normal"
    ).group_by(TrafficModel.attack_type).order_by(func.count(TrafficModel.id).desc()).first()
    latest_attack = TrafficModel.query.filter(
        TrafficModel.attack_type.isnot(None),
        TrafficModel.attack_type != "Normal"
    ).order_by(TrafficModel.upload_time.desc()).first()
    posture = {
        "today_detection_count": today_detection_count,
        "today_malicious_count": today_malicious_count,
        "high_event_count": high_event_count,
        "open_event_count": open_event_count,
        "common_attack_type": common_attack[0] if common_attack else "暂无",
        "latest_attack_time": latest_attack.upload_time.strftime('%Y-%m-%d %H:%M:%S') if latest_attack else "暂无"
    }
    return render_template("index.html", traffics=traffics, posture=posture)



@bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_traffic(id):
    try:
        logging.info(f"尝试删除记录，ID: {id}")
        traffic = TrafficModel.query.get_or_404(id)
        logging.info(f"找到记录: {traffic}")
        db.session.delete(traffic)
        db.session.commit()
        logging.info(f"成功删除记录，ID: {id}")
        logRecord = LogModel(op_user=g.user.username, op_name="删除记录")
        db.session.add(logRecord)
        db.session.commit()
        return redirect(url_for('qa.index'))
    except Exception as e:
        logging.error(f"删除记录时出现错误，ID: {id}, 错误信息: {str(e)}")
        return "删除记录时出现错误，请稍后重试。", 500


def perform_offline_detection():
    try:
        result = subprocess.run(
            ['python', 'utils/detect_offline.py'],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"检测失败: {result.stderr}"
    except Exception as e:
        return f"发生错误: {str(e)}"


@bp.route('/qa/start_offline_detection', methods=['GET', 'POST'])
@login_required
def start_offline_detection():
    if request.method == 'POST':
        detection_result = perform_offline_detection()
        logRecord = LogModel(op_user=g.user.username, op_name="实时监控")
        db.session.add(logRecord)
        db.session.commit()
        print(detection_result)
        return jsonify({'result': detection_result})
    return render_template("offline_detection.html")


@bp.route('/qa/data', methods=['get'])
@login_required
def capture_data():
    return render_template("capture_data.html")


@bp.route('/start_capture', methods=['POST'])
@login_required
def start_capture():
    try:
        # 抓包时长（秒）
        capture_duration = 10
        output_filename = f"traffic_{int(time.time())}.pcap"
        output_path = os.path.join("captured_traffic", output_filename)

        # 开始抓包
        print("开始抓包...")
        packets = sniff(timeout=capture_duration)
        wrpcap(output_path, packets)
        print("抓包完成，文件已保存。")

        # 返回抓包结果
        filesize = os.path.getsize(output_path)
        capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        logRecord = LogModel(op_user=g.user.username, op_name="抓包数据")
        db.session.add(logRecord)
        db.session.commit()
        return jsonify({
            'success': True,
            'filename': output_filename,
            'filesize': filesize,
            'capture_time': capture_time,
        })
    except Exception as e:
        print(f"抓包失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
        })
@bp.route("/savelog", methods=['POST'])
@login_required
def savelog():
    logRecord = LogModel(op_user=g.user.username, op_name="实时监控")
    db.session.add(logRecord)
    db.session.commit()
    return jsonify({"success": True})

@bp.route('/start_monitor', methods=['POST'])
@login_required
def start_monitor():
    try:
        # 抓包时长（秒）
        capture_duration = 1
        output_filename = f"traffic_{int(time.time())}.pcap"
        output_path = os.path.join("captured_traffic", output_filename)

        # 开始抓包
        print("开始抓包...")
        packets = sniff(timeout=capture_duration)
        wrpcap(output_path, packets)
        print("抓包完成，文件已保存。")

        # 返回抓包结果
        filesize = os.path.getsize(output_path)
        capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        analysis_result = predict(output_path)
        result = ""
        for packet in packets:
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
            if 'TCP' in packet:
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
                result += f"{src_ip} : {src_port}, {dst_ip} : {dst_port}"+"\n"
        return jsonify({
            'success': True,
            'filename': output_filename,
            # 'filesize': filesize,
            # 'capture_time': capture_time,
            'analysis_result': analysis_result,
            'attack_type': analysis_result.get("attack_type"),
            'confidence': analysis_result.get("confidence"),
            'is_malicious': analysis_result.get("attack_type") != "Normal",
            'result': result
        })
    except Exception as e:
        print(f"抓包失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
        })


ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def summarize_detection(analysis_result):
    attack_distribution = analysis_result.get('attack_distribution') or {}
    total = sum(attack_distribution.values()) or analysis_result.get('total_packets', 0) or 0
    malicious_count = sum(
        count for attack_type, count in attack_distribution.items()
        if attack_type != 'Normal'
    )
    malicious_ratio = round((malicious_count / total) * 100, 2) if total else 0.0
    risk_score = min(100.0, round(malicious_ratio, 2))

    attack_candidates = {
        attack_type: count for attack_type, count in attack_distribution.items()
        if attack_type != 'Normal'
    }
    if attack_candidates:
        attack_type = max(attack_candidates.items(), key=lambda item: item[1])[0]
    else:
        attack_type = 'Normal'

    return attack_type, malicious_ratio, risk_score


def build_enhanced_detection_result(analysis_result):
    model_attack_type = analysis_result.get("attack_type") or "Normal"
    model_confidence = analysis_result.get("confidence")
    protocol_distribution = analysis_result.get("protocol_distribution", {})
    attack_distribution = analysis_result.get("attack_distribution", {})
    evidence = analysis_result.get("evidence", {})

    rule_hits = run_rule_engine(evidence)
    ip_list = evidence.get("src_ips", []) + evidence.get("dst_ips", [])
    threat_intel_hits = check_ip_reputation(ip_list)
    fusion = fuse_detection_result(
        model_attack_type=model_attack_type,
        model_confidence=model_confidence,
        rule_hits=rule_hits,
        threat_intel_hits=threat_intel_hits
    )

    final_attack_type = fusion["final_attack_type"]
    total = sum(attack_distribution.values()) or analysis_result.get("total_packets", 0) or 0
    malicious_count = sum(
        count for attack_type, count in attack_distribution.items()
        if attack_type != "Normal"
    )
    malicious_ratio = round((malicious_count / total) * 100, 2) if total else 0.0
    important_port = bool(set(evidence.get("dst_ports", [])).intersection(IMPORTANT_PORTS))

    risk_score = calculate_risk_score(
        attack_type=final_attack_type,
        malicious_ratio=malicious_ratio,
        threat_intel_hit=bool(threat_intel_hits),
        important_port=important_port,
        model_confidence=model_confidence,
        packet_count=evidence.get("packet_count")
    )
    severity = score_to_severity(risk_score)
    explanation = explain_attack(final_attack_type, fusion["fusion_notes"])
    recommendations = get_recommendations(final_attack_type)

    if final_attack_type == "Normal":
        detection_text = "流量正常"
    else:
        detection_text = "检测到疑似 {} 流量".format(final_attack_type)

    result = build_detection_result(
        attack_type=final_attack_type,
        attack_name=explanation.get("attack_name"),
        attack_summary=explanation.get("summary"),
        detection_result=detection_text,
        protocol_distribution=protocol_distribution,
        attack_distribution=attack_distribution,
        risk_score=risk_score,
        severity=severity,
        severity_label=severity_cn(severity),
        confidence=model_confidence,
        explanation=explanation.get("reasons", []),
        recommendations=recommendations,
        threat_intel={"hits": threat_intel_hits, "hit_count": len(threat_intel_hits)},
        rule_hits=rule_hits,
        evidence=evidence,
        topk=analysis_result.get("topk", []),
        fusion_notes=fusion["fusion_notes"]
    )
    result["attack_percentages"] = analysis_result.get("attack_percentages", {})
    result["total_packets"] = analysis_result.get("total_packets", 0)
    result["packet_count"] = analysis_result.get("packet_count", evidence.get("packet_count", 0))
    result["malicious_ratio"] = malicious_ratio
    result["model_name"] = analysis_result.get("model_name", "Tabular Transformer")
    result["feature_type"] = analysis_result.get("feature_type", "CICIDS2017 flow statistics")
    result["detection_pipeline"] = analysis_result.get(
        "detection_pipeline",
        "PCAP -> Flow 特征提取 -> Tabular Transformer -> 风险评分 + 规则引擎 + 威胁情报"
    )
    result["input_diagnostics"] = analysis_result.get("input_diagnostics", {})
    result["inference_device"] = analysis_result.get("device")
    return result, malicious_ratio


@bp.route("/analyze", methods=['GET', 'POST'])
@login_required
def upload_essay():
    if request.method == 'POST':
        # 检查是否有文件上传
        if 'pcap_file' not in request.files:
            flash('没有选择文件')
            return redirect(request.url)

        pcap_file = request.files['pcap_file']

        is_valid, error = validate_pcap_upload(pcap_file)
        if not is_valid:
            flash(error)
            return redirect(request.url)

        if pcap_file and allowed_file(pcap_file.filename):
            # 安全处理文件名
            save_dir = 'captured_traffic'
            save_path, filename = build_safe_upload_path(save_dir, pcap_file.filename)

            # 保存文件
            pcap_file.save(save_path)

            # 获取文件大小
            file_size = os.path.getsize(save_path)

            try:
                analysis_result = predict(save_path)
            except Exception as exc:
                logging.exception("PCAP 文件解析或检测失败")
                flash(f"PCAP 文件解析失败：{exc}")
                return redirect(request.url)

            enhanced_result, malicious_ratio = build_enhanced_detection_result(analysis_result)

            # 保存分析结果到数据库
            traffic_record = TrafficModel(
                file_name=filename,
                file_size=file_size,
                detection_result=to_json(enhanced_result),
                attack_type=enhanced_result["attack_type"],
                protocol_distribution=to_json(enhanced_result.get('protocol_distribution', {})),
                attack_distribution=to_json(enhanced_result.get('attack_distribution', {})),
                malicious_ratio=malicious_ratio,
                risk_score=enhanced_result["risk_score"],
                severity=enhanced_result["severity"],
                confidence=enhanced_result.get("confidence"),
                evidence_json=to_json(enhanced_result.get("evidence", {}))
            )

            db.session.add(traffic_record)
            db.session.commit()

            if enhanced_result["attack_type"] != "Normal" or enhanced_result["risk_score"] >= 40:
                incident = create_incident_from_traffic(traffic_record.id, use_llm=True)
                if incident:
                    return redirect(url_for("soc.incident_detail", incident_id=incident.id))

            return render_template('result.html', result=enhanced_result)

        flash('仅支持 .pcap 或 .pcapng 文件')
        return redirect(request.url)

    return render_template('upload.html')

@bp.route("/qa/detail/<qa_id>")
@login_required
def qa_detail(qa_id):
    question = QuestionModel.query.get(qa_id)
    return render_template("detail.html", question=question)


# @bp.route("/answer/public", methods=['POST'])
@bp.post("/answer/public")
@login_required
def public_answer():
    form = AnswerForm(request.form)
    if form.validate():
        content = form.content.data
        question_id = form.question_id.data
        answer = AnswerModel(content=content, question_id=question_id, author_id=g.user.id)
        db.session.add(answer)
        db.session.commit()
        return redirect(url_for("qa.qa_detail", qa_id=question_id))
    else:
        print(form.errors)
        return redirect(url_for("qa.qa_detail", qa_id=request.form.get("question_id")))
