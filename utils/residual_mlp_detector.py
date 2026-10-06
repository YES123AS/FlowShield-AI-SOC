import os
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from scapy.all import IP, TCP, UDP, rdpcap


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = BASE_DIR / "models" / "residual_mlp_best.pt"
DEFAULT_SCALER_PATH = BASE_DIR / "models" / "scaler.joblib"
MODEL_NAME = "Residual MLP"
FEATURE_TYPE = "CICIDS2017 flow statistics"
DETECTION_PIPELINE = "PCAP -> Flow 特征提取 -> Residual MLP -> 风险评分 + 规则引擎 + 威胁情报"


class ResidualBlock(nn.Module):
    def __init__(self, dim: int, dropout: float = 0.25):
        super().__init__()
        self.block = nn.Sequential(
            nn.BatchNorm1d(dim),
            nn.Linear(dim, dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.Dropout(dropout),
        )
        self.activation = nn.GELU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.activation(x + self.block(x))


class ResidualMLP(nn.Module):
    def __init__(
        self,
        input_dim: int,
        num_classes: int,
        hidden_dim: int = 256,
        num_blocks: int = 3,
        dropout: float = 0.25,
    ):
        super().__init__()
        self.input_layer = nn.Sequential(
            nn.BatchNorm1d(input_dim),
            nn.Linear(input_dim, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.res_blocks = nn.Sequential(
            *[ResidualBlock(hidden_dim, dropout=dropout) for _ in range(num_blocks)]
        )
        self.classifier = nn.Sequential(
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, 128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.input_layer(x)
        x = self.res_blocks(x)
        return self.classifier(x)


def _artifact_path(env_name: str, default_path: Path) -> Path:
    configured = os.getenv(env_name)
    if configured:
        return Path(configured)
    return default_path


def _safe_stats(values):
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return {
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "var": 0.0,
            "sum": 0.0,
        }
    return {
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "var": float(np.var(arr)),
        "sum": float(np.sum(arr)),
    }


def _iat(values):
    if len(values) < 2:
        return []
    values = sorted(float(value) for value in values)
    return [max(values[index] - values[index - 1], 0.0) for index in range(1, len(values))]


def _tcp_flag_count(packets, flag):
    return sum(1 for pkt in packets if pkt.haslayer(TCP) and flag in str(pkt[TCP].flags))


def _header_length(pkt):
    ip_header = int(pkt[IP].ihl or 0) * 4 if pkt.haslayer(IP) else 0
    if pkt.haslayer(TCP):
        return ip_header + int(pkt[TCP].dataofs or 0) * 4
    if pkt.haslayer(UDP):
        return ip_header + 8
    return ip_header


def _payload_length(pkt):
    if pkt.haslayer(TCP):
        return len(bytes(pkt[TCP].payload))
    if pkt.haslayer(UDP):
        return len(bytes(pkt[UDP].payload))
    return 0


def _active_idle_stats(timestamps, idle_threshold_seconds=5.0):
    times = sorted(float(value) for value in timestamps)
    if not times:
        return _safe_stats([]), _safe_stats([])

    active_durations = []
    idle_durations = []
    active_start = times[0]
    previous = times[0]
    for current in times[1:]:
        gap = max(current - previous, 0.0)
        if gap > idle_threshold_seconds:
            active_durations.append(max(previous - active_start, 0.0) * 1_000_000)
            idle_durations.append(gap * 1_000_000)
            active_start = current
        previous = current
    active_durations.append(max(previous - active_start, 0.0) * 1_000_000)
    return _safe_stats(active_durations), _safe_stats(idle_durations)


def _window_size(pkt):
    if pkt.haslayer(TCP):
        return int(pkt[TCP].window)
    return 0


def _flow_key(pkt):
    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
    src_port = int(pkt[TCP].sport) if pkt.haslayer(TCP) else int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0
    dst_port = int(pkt[TCP].dport) if pkt.haslayer(TCP) else int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0
    src = pkt[IP].src
    dst = pkt[IP].dst
    forward = (src, dst, src_port, dst_port, proto)
    backward = (dst, src, dst_port, src_port, proto)
    return min(forward, backward), forward


def extract_cicids_features(packets):
    flows = defaultdict(lambda: {"forward": [], "backward": [], "origin": None})

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            continue
        canonical_key, packet_key = _flow_key(pkt)
        if flows[canonical_key]["origin"] is None:
            flows[canonical_key]["origin"] = packet_key
        direction = "forward" if packet_key == flows[canonical_key]["origin"] else "backward"
        flows[canonical_key][direction].append(pkt)

    rows = []
    raw_rows = []

    for canonical_key, directions in flows.items():
        src, dst, src_port, dst_port, proto = directions["origin"] or canonical_key
        fwd_packets = directions["forward"]
        bwd_packets = directions["backward"]
        all_packets = fwd_packets + bwd_packets
        if not all_packets:
            continue

        timestamps = [float(pkt.time) for pkt in all_packets if hasattr(pkt, "time")]
        fwd_times = [float(pkt.time) for pkt in fwd_packets if hasattr(pkt, "time")]
        bwd_times = [float(pkt.time) for pkt in bwd_packets if hasattr(pkt, "time")]

        duration_seconds = max(max(timestamps) - min(timestamps), 1e-6) if timestamps else 1e-6
        duration_micro = duration_seconds * 1_000_000

        fwd_lengths = [len(pkt) for pkt in fwd_packets]
        bwd_lengths = [len(pkt) for pkt in bwd_packets]
        all_lengths = [len(pkt) for pkt in all_packets]
        fwd_stats = _safe_stats(fwd_lengths)
        bwd_stats = _safe_stats(bwd_lengths)
        packet_stats = _safe_stats(all_lengths)
        flow_iat = _safe_stats([value * 1_000_000 for value in _iat(timestamps)])
        fwd_iat_values = [value * 1_000_000 for value in _iat(fwd_times)]
        bwd_iat_values = [value * 1_000_000 for value in _iat(bwd_times)]
        fwd_iat = _safe_stats(fwd_iat_values)
        bwd_iat = _safe_stats(bwd_iat_values)

        fwd_count = len(fwd_packets)
        bwd_count = len(bwd_packets)
        total_count = fwd_count + bwd_count
        fwd_bytes = int(sum(fwd_lengths))
        bwd_bytes = int(sum(bwd_lengths))
        fwd_header_length = int(sum(_header_length(pkt) for pkt in fwd_packets))
        bwd_header_length = int(sum(_header_length(pkt) for pkt in bwd_packets))

        active, idle = _active_idle_stats(timestamps)

        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration_micro,
            "Total Fwd Packets": fwd_count,
            "Total Backward Packets": bwd_count,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Fwd Packet Length Max": fwd_stats["max"],
            "Fwd Packet Length Min": fwd_stats["min"],
            "Fwd Packet Length Mean": fwd_stats["mean"],
            "Fwd Packet Length Std": fwd_stats["std"],
            "Bwd Packet Length Max": bwd_stats["max"],
            "Bwd Packet Length Min": bwd_stats["min"],
            "Bwd Packet Length Mean": bwd_stats["mean"],
            "Bwd Packet Length Std": bwd_stats["std"],
            "Flow Bytes/s": (fwd_bytes + bwd_bytes) / duration_seconds,
            "Flow Packets/s": total_count / duration_seconds,
            "Flow IAT Mean": flow_iat["mean"],
            "Flow IAT Std": flow_iat["std"],
            "Flow IAT Max": flow_iat["max"],
            "Flow IAT Min": flow_iat["min"],
            "Fwd IAT Total": fwd_iat["sum"],
            "Fwd IAT Mean": fwd_iat["mean"],
            "Fwd IAT Std": fwd_iat["std"],
            "Fwd IAT Max": fwd_iat["max"],
            "Fwd IAT Min": fwd_iat["min"],
            "Bwd IAT Total": bwd_iat["sum"],
            "Bwd IAT Mean": bwd_iat["mean"],
            "Bwd IAT Std": bwd_iat["std"],
            "Bwd IAT Max": bwd_iat["max"],
            "Bwd IAT Min": bwd_iat["min"],
            "Fwd PSH Flags": _tcp_flag_count(fwd_packets, "P"),
            "Bwd PSH Flags": _tcp_flag_count(bwd_packets, "P"),
            "Fwd URG Flags": _tcp_flag_count(fwd_packets, "U"),
            "Bwd URG Flags": _tcp_flag_count(bwd_packets, "U"),
            "Fwd Header Length": fwd_header_length,
            "Bwd Header Length": bwd_header_length,
            "Fwd Packets/s": fwd_count / duration_seconds,
            "Bwd Packets/s": bwd_count / duration_seconds,
            "Min Packet Length": packet_stats["min"],
            "Max Packet Length": packet_stats["max"],
            "Packet Length Mean": packet_stats["mean"],
            "Packet Length Std": packet_stats["std"],
            "Packet Length Variance": packet_stats["var"],
            "FIN Flag Count": _tcp_flag_count(all_packets, "F"),
            "SYN Flag Count": _tcp_flag_count(all_packets, "S"),
            "RST Flag Count": _tcp_flag_count(all_packets, "R"),
            "PSH Flag Count": _tcp_flag_count(all_packets, "P"),
            "ACK Flag Count": _tcp_flag_count(all_packets, "A"),
            "URG Flag Count": _tcp_flag_count(all_packets, "U"),
            "CWE Flag Count": _tcp_flag_count(all_packets, "C"),
            "ECE Flag Count": _tcp_flag_count(all_packets, "E"),
            "Down/Up Ratio": bwd_count / max(fwd_count, 1),
            "Average Packet Size": packet_stats["mean"],
            "Avg Fwd Segment Size": fwd_stats["mean"],
            "Avg Bwd Segment Size": bwd_stats["mean"],
            "Fwd Header Length.1": fwd_header_length,
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": fwd_count,
            "Subflow Fwd Bytes": fwd_bytes,
            "Subflow Bwd Packets": bwd_count,
            "Subflow Bwd Bytes": bwd_bytes,
            "Init_Win_bytes_forward": _window_size(fwd_packets[0]) if fwd_packets else 0,
            "Init_Win_bytes_backward": _window_size(bwd_packets[0]) if bwd_packets else 0,
            "act_data_pkt_fwd": sum(1 for pkt in fwd_packets if _payload_length(pkt) > 0),
            "min_seg_size_forward": min((_header_length(pkt) for pkt in fwd_packets), default=0),
            "Active Mean": active["mean"],
            "Active Std": active["std"],
            "Active Max": active["max"],
            "Active Min": active["min"],
            "Idle Mean": idle["mean"],
            "Idle Std": idle["std"],
            "Idle Max": idle["max"],
            "Idle Min": idle["min"],
        }
        rows.append(row)
        raw_rows.append({
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "num_packets": total_count,
            "total_bytes": fwd_bytes + bwd_bytes,
            "flow_duration": duration_seconds,
        })

    return pd.DataFrame(rows), pd.DataFrame(raw_rows)


def build_evidence(packets, raw_feature_df):
    src_ips = sorted(set(raw_feature_df.get("src_ip", pd.Series(dtype=str)).dropna().astype(str).tolist()))
    dst_ips = sorted(set(raw_feature_df.get("dst_ip", pd.Series(dtype=str)).dropna().astype(str).tolist()))
    dst_ports = sorted(set(
        int(port) for port in raw_feature_df.get("dst_port", pd.Series(dtype=int)).dropna().tolist()
        if int(port) > 0
    ))
    timestamps = []
    for pkt in packets:
        if hasattr(pkt, "time"):
            try:
                timestamps.append(float(pkt.time))
            except (TypeError, ValueError):
                pass
    duration = max(timestamps) - min(timestamps) if timestamps else 0
    total_bytes = int(sum(len(pkt) for pkt in packets))
    protocol_counts = raw_feature_df["protocol"].value_counts().to_dict() if "protocol" in raw_feature_df else {}
    dst_port_counts = (
        raw_feature_df["dst_port"].value_counts().to_dict()
        if "dst_port" in raw_feature_df else {}
    )

    return {
        "packet_count": int(len(packets)),
        "flow_count": int(len(raw_feature_df)),
        "unique_src_ips": int(len(src_ips)),
        "unique_dst_ips": int(len(dst_ips)),
        "unique_dst_ports": int(len(dst_ports)),
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "dst_ports": dst_ports,
        "dst_port_counts": {
            str(int(port)): int(count)
            for port, count in dst_port_counts.items()
            if int(port) > 0
        },
        "bytes_out": total_bytes,
        "duration": round(max(duration, 0), 3),
        "protocol_counts": {str(key): int(value) for key, value in protocol_counts.items()},
    }


@lru_cache(maxsize=1)
def load_detector():
    model_path = _artifact_path("RESIDUAL_MLP_MODEL_PATH", DEFAULT_MODEL_PATH)
    scaler_path = _artifact_path("RESIDUAL_MLP_SCALER_PATH", DEFAULT_SCALER_PATH)

    if not model_path.exists():
        raise FileNotFoundError(
            f"未找到 Residual MLP 权重文件：{model_path}。"
            "请将 residual_mlp_best.pt 放到 models/ 目录，或设置 RESIDUAL_MLP_MODEL_PATH。"
        )
    if not scaler_path.exists():
        raise FileNotFoundError(
            f"未找到 Residual MLP 标准化器：{scaler_path}。"
            "训练脚本会同时输出 scaler.joblib；请将它放到 models/ 目录，或设置 RESIDUAL_MLP_SCALER_PATH。"
        )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(model_path, map_location=device)
    feature_columns = checkpoint.get("feature_columns")
    classes = checkpoint.get("classes")
    if not feature_columns or not classes:
        raise ValueError("residual_mlp_best.pt 中缺少 feature_columns 或 classes，无法部署推理。")

    model = ResidualMLP(
        input_dim=int(checkpoint.get("input_dim", len(feature_columns))),
        num_classes=int(checkpoint.get("num_classes", len(classes))),
        hidden_dim=int(checkpoint.get("hidden_dim", 256)),
        num_blocks=int(checkpoint.get("num_blocks", 3)),
        dropout=float(checkpoint.get("dropout", 0.25)),
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()

    scaler = joblib.load(scaler_path)
    return model, scaler, list(feature_columns), list(classes), device


def _prepare_features(feature_df, feature_columns):
    feature_df = feature_df.copy()
    for column in feature_columns:
        if column not in feature_df.columns:
            feature_df[column] = 0
    feature_df = feature_df[feature_columns]
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    return feature_df.astype(np.float32)


def predict_pcap(save_path):
    if not os.path.exists(save_path):
        raise ValueError("PCAP file not found")

    packets = rdpcap(save_path)
    if len(packets) == 0:
        return {
            "status": "No packets found in file",
            "attack_type": "Normal",
            "confidence": None,
            "topk": [],
            "model_name": MODEL_NAME,
            "feature_type": FEATURE_TYPE,
            "detection_pipeline": DETECTION_PIPELINE,
            "total_packets": 0,
            "packet_count": 0,
            "attack_distribution": {"Normal": 0},
            "attack_percentages": {"Normal": 0},
            "protocol_distribution": {},
            "details": {},
            "evidence": {},
            "prediction_details": [],
        }

    feature_df, raw_feature_df = extract_cicids_features(packets)
    evidence = build_evidence(packets, raw_feature_df)
    if feature_df.empty:
        return {
            "status": "No supported TCP/UDP IP flows found in file",
            "attack_type": "Normal",
            "confidence": None,
            "topk": [],
            "total_packets": 0,
            "packet_count": evidence["packet_count"],
            "attack_distribution": {"Normal": 0},
            "attack_percentages": {"Normal": 0},
            "protocol_distribution": evidence["protocol_counts"],
            "evidence": evidence,
            "prediction_details": [],
            "model_name": MODEL_NAME,
            "feature_type": FEATURE_TYPE,
            "detection_pipeline": DETECTION_PIPELINE,
        }

    model, scaler, feature_columns, classes, device = load_detector()
    prepared = _prepare_features(feature_df, feature_columns)
    scaled = scaler.transform(prepared.values).astype(np.float32)

    with torch.no_grad():
        logits = model(torch.from_numpy(scaled).to(device))
        probs = torch.softmax(logits, dim=1).cpu().numpy()

    pred_indices = np.argmax(probs, axis=1)
    predictions = [classes[index] for index in pred_indices]
    attack_counts = {label: 0 for label in classes}
    attack_counts.update(Counter(predictions))
    total_flows = len(predictions)

    attack_percentages = {
        name: (count / total_flows) * 100 if total_flows else 0
        for name, count in attack_counts.items()
    }

    main_attack = max(attack_counts.items(), key=lambda item: item[1])
    if main_attack[0] != "Normal" and main_attack[1] > total_flows * 0.3:
        status = f"检测到{main_attack[0]}攻击（占比{attack_percentages[main_attack[0]]:.1f}%）"
    else:
        status = "流量正常"
        main_attack = ("Normal", attack_counts.get("Normal", 0))

    prediction_details = []
    for row_index, (label, row_probs) in enumerate(zip(predictions, probs)):
        top_indices = np.argsort(row_probs)[::-1][:3]
        prediction_details.append({
            "flow_index": row_index,
            "attack_type": label,
            "confidence": float(row_probs[pred_indices[row_index]]),
            "topk": [
                {"label": classes[index], "score": float(row_probs[index])}
                for index in top_indices
            ],
        })

    matching_confidences = [
        item["confidence"] for item in prediction_details
        if item["attack_type"] == main_attack[0]
    ]
    confidence_pool = matching_confidences or [item["confidence"] for item in prediction_details]
    confidence = float(np.mean(confidence_pool)) if confidence_pool else None

    topk_summary = []
    for detail in prediction_details:
        if detail["attack_type"] == main_attack[0]:
            topk_summary = detail["topk"]
            break

    return {
        "status": status,
        "attack_type": main_attack[0],
        "confidence": confidence,
        "topk": topk_summary,
        "total_packets": total_flows,
        "packet_count": evidence["packet_count"],
        "attack_distribution": attack_counts,
        "attack_percentages": attack_percentages,
        "protocol_distribution": evidence["protocol_counts"],
        "evidence": evidence,
        "prediction_details": prediction_details[:50],
        "feature_columns": feature_columns,
        "model_name": MODEL_NAME,
        "feature_type": FEATURE_TYPE,
        "detection_pipeline": DETECTION_PIPELINE,
    }
