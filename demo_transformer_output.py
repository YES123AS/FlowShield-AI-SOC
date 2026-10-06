"""
独立 Transformer 检测输出 Demo
============================

用途：
1. 命令行输入 .pcap / .pcapng 文件，直接输出 Transformer 检测 JSON。
2. 也可以启动一个轻量 Flask 上传接口，POST 一个 PCAP 文件后返回同样 JSON。

示例：
    python demo_transformer_output.py captured_traffic/test.pcap
    python demo_transformer_output.py captured_traffic/test.pcap --out outputs/demo_result.json
    python demo_transformer_output.py --serve --port 5055

接口：
    POST http://127.0.0.1:5055/api/predict
    form-data:
        pcap_file: <your.pcap>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import warnings
from pathlib import Path
from typing import Any


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
warnings.filterwarnings(
    "ignore",
    message=r"enable_nested_tensor is True.*",
    category=UserWarning,
)

PROJECT_ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = PROJECT_ROOT / "uploads" / "demo_transformer"
DEFAULT_CLASSES = [
    "Normal",
    "DDoS",
    "DoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Malware",
]
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".pacp"}  # .pacp 用于兼容常见拼写错误


def _safe_float(value: Any, default: float | None = None) -> float | None:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_list(value: Any, limit: int = 50) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)[:limit]
    return [value]


def _normalize_topk(topk: Any, limit: int = 3) -> list[dict[str, Any]]:
    normalized = []
    if not isinstance(topk, list):
        return normalized
    for item in topk[:limit]:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "label": item.get("label", "Unknown"),
            "score": _safe_float(item.get("score"), 0.0),
        })
    return normalized


def _normalize_distribution(raw: Any, classes: list[str]) -> dict[str, int]:
    result = {label: 0 for label in classes}
    if isinstance(raw, dict):
        for key, value in raw.items():
            result[str(key)] = _safe_int(value, 0)
    return result


def _normalize_percentages(raw: Any, attack_distribution: dict[str, int]) -> dict[str, float]:
    if isinstance(raw, dict) and raw:
        return {
            label: round(_safe_float(raw.get(label), 0.0) or 0.0, 2)
            for label in attack_distribution
        }

    total = sum(attack_distribution.values())
    if total <= 0:
        return {label: 0.0 for label in attack_distribution}
    return {
        label: round(count / total * 100, 2)
        for label, count in attack_distribution.items()
    }


def _normalize_prediction_details(raw: Any, limit: int = 100) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []

    details = []
    for item in raw[:limit]:
        if not isinstance(item, dict):
            continue
        details.append({
            "flow_index": _safe_int(item.get("flow_index")),
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "src_port": _safe_int(item.get("src_port")),
            "dst_port": _safe_int(item.get("dst_port")),
            "protocol": item.get("protocol"),
            "attack_type": item.get("attack_type", "Unknown"),
            "confidence": _safe_float(item.get("confidence"), 0.0),
            "topk": _normalize_topk(item.get("topk"), limit=3),
        })
    return details


def normalize_detection_result(model_result: dict[str, Any]) -> dict[str, Any]:
    """
    将现有 utils.predict.predict() 的结果规整为答辩/Agent 演示所需的固定 JSON Schema。

    注意：
    - total_packets 在现有 Transformer 检测器中表示 total_flows，即聚合后的 Flow 数量。
    - packet_count 表示原始 PCAP 包数量。
    """
    classes = list(model_result.get("feature_classes") or model_result.get("classes") or DEFAULT_CLASSES)
    attack_distribution = _normalize_distribution(
        model_result.get("attack_distribution"),
        classes,
    )
    attack_percentages = _normalize_percentages(
        model_result.get("attack_percentages"),
        attack_distribution,
    )

    evidence_raw = model_result.get("evidence") or {}
    protocol_distribution = (
        model_result.get("protocol_distribution")
        or evidence_raw.get("protocol_counts")
        or {}
    )

    evidence = {
        "src_ips": _safe_list(evidence_raw.get("src_ips"), limit=50),
        "dst_ips": _safe_list(evidence_raw.get("dst_ips"), limit=50),
        "dst_ports": [_safe_int(port) for port in _safe_list(evidence_raw.get("dst_ports"), limit=50)],
        "packet_count": _safe_int(
            evidence_raw.get("packet_count"),
            _safe_int(model_result.get("packet_count")),
        ),
    }

    return {
        "status": model_result.get("status", "未知检测状态"),
        "attack_type": model_result.get("attack_type", "Unknown"),
        "confidence": _safe_float(model_result.get("confidence")),
        "topk": _normalize_topk(model_result.get("topk"), limit=3),
        "total_packets": _safe_int(model_result.get("total_packets")),
        "packet_count": _safe_int(model_result.get("packet_count"), evidence["packet_count"]),
        "attack_distribution": attack_distribution,
        "attack_percentages": attack_percentages,
        "protocol_distribution": {
            str(key): _safe_int(value)
            for key, value in dict(protocol_distribution).items()
        },
        "evidence": evidence,
        "prediction_details": _normalize_prediction_details(
            model_result.get("prediction_details"),
            limit=100,
        ),
        "model_name": model_result.get("model_name", "Tabular Transformer"),
        "feature_type": model_result.get("feature_type", "CICIDS2017 flow statistics"),
        "detection_pipeline": model_result.get(
            "detection_pipeline",
            "PCAP -> Flow 特征提取 -> Tabular Transformer -> 风险评分 + 规则引擎 + 威胁情报",
        ),
    }


def detect_pcap(pcap_path: str | Path) -> dict[str, Any]:
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP 文件不存在：{pcap_path}")
    if pcap_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("仅支持 .pcap / .pcapng 文件")

    # 强制 demo 使用 Transformer 后端；如果用户环境变量已显式设置，也尊重当前设置。
    os.environ.setdefault("DETECTOR_BACKEND", "transformer")

    from utils.predict import predict

    raw_result = predict(str(pcap_path))
    return normalize_detection_result(raw_result)


def write_json(result: dict[str, Any], output_path: str | Path | None = None) -> str:
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
    return text


def _safe_filename(filename: str) -> str:
    name = Path(filename or "upload.pcap").name
    name = re.sub(r"[^0-9A-Za-z._\-\u4e00-\u9fff]", "_", name)
    return name or "upload.pcap"


def create_demo_app():
    from flask import Flask, Response, jsonify, request

    app = Flask(__name__)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Transformer PCAP Detection Demo</title>
  <style>
    body { font-family: "Microsoft YaHei", Arial, sans-serif; margin: 48px; background: #f8fafc; color: #1f2937; }
    .card { max-width: 760px; background: white; border: 1px solid #bfdbfe; border-radius: 18px; padding: 28px; box-shadow: 0 8px 24px rgba(37,99,235,.08); }
    h1 { color: #1e40af; margin-top: 0; }
    .muted { color: #6b7280; }
    input, button { font-size: 16px; }
    button { background: #2563eb; color: white; border: 0; border-radius: 10px; padding: 10px 18px; cursor: pointer; }
    pre { background: #f5f7fa; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; white-space: pre-wrap; }
  </style>
</head>
<body>
  <div class="card">
    <h1>FlowShield Transformer 输出 Demo</h1>
    <p class="muted">上传 .pcap / .pcapng 文件，返回模型检测 JSON。</p>
    <form id="form">
      <input type="file" name="pcap_file" accept=".pcap,.pcapng,.pacp" required>
      <button type="submit">开始检测</button>
    </form>
    <pre id="result">等待上传...</pre>
  </div>
  <script>
    const form = document.getElementById('form');
    const result = document.getElementById('result');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      result.textContent = '检测中，请稍候...';
      const fd = new FormData(form);
      const resp = await fetch('/api/predict', { method: 'POST', body: fd });
      result.textContent = await resp.text();
    });
  </script>
</body>
</html>
"""

    @app.post("/api/predict")
    def api_predict():
        upload = request.files.get("pcap_file") or request.files.get("file")
        if upload is None:
            return jsonify({"success": False, "error": "请使用字段 pcap_file 上传 PCAP 文件"}), 400

        filename = _safe_filename(upload.filename)
        suffix = Path(filename).suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            return jsonify({"success": False, "error": "仅支持 .pcap / .pcapng 文件"}), 400

        save_path = UPLOAD_DIR / filename
        upload.save(save_path)

        try:
            result = detect_pcap(save_path)
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

        return Response(
            json.dumps(result, ensure_ascii=False, indent=2),
            mimetype="application/json; charset=utf-8",
        )

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="独立 Transformer PCAP 检测输出 Demo")
    parser.add_argument("pcap", nargs="?", help="待检测的 .pcap / .pcapng 文件路径")
    parser.add_argument("--out", help="可选：将 JSON 输出保存到指定文件")
    parser.add_argument("--serve", action="store_true", help="启动 Flask 上传接口")
    parser.add_argument("--host", default="127.0.0.1", help="Flask 监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=5055, help="Flask 监听端口，默认 5055")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.serve:
        app = create_demo_app()
        print(f"Transformer Demo 已启动：http://{args.host}:{args.port}")
        print("API: POST /api/predict，form-data 字段名：pcap_file")
        app.run(host=args.host, port=args.port, debug=False)
        return

    if not args.pcap:
        raise SystemExit("请提供 PCAP 文件路径，或使用 --serve 启动上传 Demo。")

    result = detect_pcap(args.pcap)
    print(write_json(result, args.out))


if __name__ == "__main__":
    main()
