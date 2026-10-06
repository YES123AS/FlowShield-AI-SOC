import os
from collections import Counter
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn
from scapy.all import rdpcap

from utils.residual_mlp_detector import (
    _prepare_features,
    build_evidence,
    extract_cicids_features,
)


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = BASE_DIR / "models" / "transformer_best.pt"
DEFAULT_SCALER_PATH = BASE_DIR / "models" / "scaler.joblib"
MODEL_NAME = "Tabular Transformer"
FEATURE_TYPE = "CICIDS2017 flow statistics"
DETECTION_PIPELINE = "PCAP -> Flow 特征提取 -> Tabular Transformer -> 风险评分 + 规则引擎 + 威胁情报"


class NumericalFeatureTokenizer(nn.Module):
    def __init__(self, num_features: int, d_token: int):
        super().__init__()
        self.weight = nn.Parameter(torch.empty(num_features, d_token))
        self.bias = nn.Parameter(torch.empty(num_features, d_token))
        nn.init.xavier_uniform_(self.weight)
        nn.init.zeros_(self.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.ndim != 2:
            raise ValueError(f"Transformer 期望二维输入 [B, F]，实际得到 {tuple(x.shape)}")
        return x.unsqueeze(-1) * self.weight.unsqueeze(0) + self.bias.unsqueeze(0)


class TabularTransformer(nn.Module):
    def __init__(
        self,
        input_dim: int,
        num_classes: int,
        d_token: int = 64,
        num_layers: int = 3,
        n_heads: int = 8,
        ff_mult: int = 4,
        dropout: float = 0.2,
        classifier_hidden: int = 128,
    ):
        super().__init__()
        if d_token % n_heads != 0:
            raise ValueError("d_token 必须能被 n_heads 整除")

        self.tokenizer = NumericalFeatureTokenizer(input_dim, d_token)
        self.cls_token = nn.Parameter(torch.zeros(1, 1, d_token))
        self.pos_embedding = nn.Parameter(torch.zeros(1, input_dim + 1, d_token))
        self.input_dropout = nn.Dropout(dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_token,
            nhead=n_heads,
            dim_feedforward=d_token * ff_mult,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.classifier = nn.Sequential(
            nn.LayerNorm(d_token),
            nn.Linear(d_token, classifier_hidden),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(classifier_hidden, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        tokens = self.tokenizer(x)
        cls = self.cls_token.expand(tokens.size(0), -1, -1)
        tokens = torch.cat([cls, tokens], dim=1)
        tokens = self.input_dropout(tokens + self.pos_embedding[:, :tokens.size(1), :])
        return self.classifier(self.encoder(tokens)[:, 0, :])


def _artifact_path(env_name: str, default_path: Path) -> Path:
    configured = os.getenv(env_name)
    return Path(configured) if configured else default_path


def _load_checkpoint(path: Path, device: torch.device):
    try:
        return torch.load(path, map_location=device, weights_only=True)
    except TypeError:
        return torch.load(path, map_location=device)


@lru_cache(maxsize=1)
def load_detector():
    model_path = _artifact_path("TRANSFORMER_MODEL_PATH", DEFAULT_MODEL_PATH)
    scaler_path = _artifact_path("TRANSFORMER_SCALER_PATH", DEFAULT_SCALER_PATH)

    if not model_path.exists():
        raise FileNotFoundError(
            f"未找到 Transformer 权重：{model_path}。"
            "请将 transformer_best.pt 放入 models/，或设置 TRANSFORMER_MODEL_PATH。"
        )
    if not scaler_path.exists():
        raise FileNotFoundError(
            f"未找到 Transformer 标准化器：{scaler_path}。"
            "请提供训练时生成的 scaler.joblib，或设置 TRANSFORMER_SCALER_PATH。"
        )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = _load_checkpoint(model_path, device)
    if checkpoint.get("model_type") not in (None, "TabularTransformer"):
        raise ValueError(f"模型类型不匹配：{checkpoint.get('model_type')}")

    feature_columns = checkpoint.get("feature_columns")
    classes = checkpoint.get("classes")
    if not feature_columns or not classes:
        raise ValueError("transformer_best.pt 缺少 feature_columns 或 classes")

    input_dim = int(checkpoint.get("input_dim", len(feature_columns)))
    num_classes = int(checkpoint.get("num_classes", len(classes)))
    if input_dim != len(feature_columns):
        raise ValueError(f"模型 input_dim={input_dim}，但特征列数量为 {len(feature_columns)}")
    if num_classes != len(classes):
        raise ValueError(f"模型 num_classes={num_classes}，但类别数量为 {len(classes)}")

    scaler = joblib.load(scaler_path)
    scaler_dim = getattr(scaler, "n_features_in_", None)
    if scaler_dim is not None and int(scaler_dim) != input_dim:
        raise ValueError(f"Scaler 维度为 {scaler_dim}，Transformer 需要 {input_dim} 维")

    model = TabularTransformer(
        input_dim=input_dim,
        num_classes=num_classes,
        d_token=int(checkpoint.get("d_token", 64)),
        num_layers=int(checkpoint.get("num_layers", 3)),
        n_heads=int(checkpoint.get("n_heads", 8)),
        ff_mult=int(checkpoint.get("ff_mult", 4)),
        dropout=float(checkpoint.get("dropout", 0.2)),
        classifier_hidden=int(checkpoint.get("classifier_hidden", 128)),
    )
    model.load_state_dict(checkpoint["model_state_dict"], strict=True)
    model.to(device)
    model.eval()
    return model, scaler, list(feature_columns), list(classes), device


def detector_status(load_model: bool = False):
    model_path = _artifact_path("TRANSFORMER_MODEL_PATH", DEFAULT_MODEL_PATH)
    scaler_path = _artifact_path("TRANSFORMER_SCALER_PATH", DEFAULT_SCALER_PATH)
    status = {
        "backend": "transformer",
        "model_name": MODEL_NAME,
        "model_path": str(model_path),
        "scaler_path": str(scaler_path),
        "model_exists": model_path.exists(),
        "scaler_exists": scaler_path.exists(),
        "ready": model_path.exists() and scaler_path.exists(),
    }
    if load_model and status["ready"]:
        _, _, features, classes, device = load_detector()
        status.update({
            "loaded": True,
            "device": str(device),
            "num_features": len(features),
            "classes": classes,
        })
    return status


def _empty_result(status: str, packet_count: int = 0, evidence=None):
    return {
        "status": status,
        "attack_type": "Normal",
        "confidence": None,
        "topk": [],
        "model_name": MODEL_NAME,
        "feature_type": FEATURE_TYPE,
        "detection_pipeline": DETECTION_PIPELINE,
        "total_packets": 0,
        "packet_count": packet_count,
        "attack_distribution": {"Normal": 0},
        "attack_percentages": {"Normal": 0},
        "protocol_distribution": (evidence or {}).get("protocol_counts", {}),
        "evidence": evidence or {},
        "prediction_details": [],
    }


def _predict_probabilities(model, values: np.ndarray, device: torch.device) -> np.ndarray:
    batch_size = max(1, int(os.getenv("TRANSFORMER_BATCH_SIZE", "512")))
    batches = []
    with torch.inference_mode():
        for start in range(0, len(values), batch_size):
            batch = torch.from_numpy(values[start:start + batch_size]).to(device)
            batches.append(torch.softmax(model(batch), dim=1).cpu().numpy())
    return np.concatenate(batches, axis=0)


def _build_input_diagnostics(scaled: np.ndarray, feature_columns):
    absolute = np.abs(scaled)
    z_threshold = float(os.getenv("TRANSFORMER_DRIFT_Z_THRESHOLD", "8.0"))
    feature_max = absolute.max(axis=0)
    top_indices = np.argsort(feature_max)[::-1][:8]
    max_abs_z = float(absolute.max()) if absolute.size else 0.0
    outlier_fraction = float(np.mean(absolute > z_threshold)) if absolute.size else 0.0
    warning = max_abs_z > 20.0 or outlier_fraction > 0.05
    return {
        "warning": warning,
        "message": (
            "输入特征与训练分布偏差较大，模型置信度可能失真；建议使用 CICFlowMeter "
            "生成与训练阶段一致的 Flow 特征。"
            if warning else
            "输入特征未发现严重的标准化分布偏移。"
        ),
        "z_threshold": z_threshold,
        "max_abs_z": max_abs_z,
        "outlier_fraction": outlier_fraction,
        "top_shifted_features": [
            {
                "feature": feature_columns[index],
                "max_abs_z": float(feature_max[index]),
            }
            for index in top_indices
        ],
    }


def predict_pcap(save_path):
    if not os.path.exists(save_path):
        raise ValueError("PCAP file not found")

    packets = rdpcap(save_path)
    if len(packets) == 0:
        return _empty_result("No packets found in file")

    feature_df, raw_feature_df = extract_cicids_features(packets)
    evidence = build_evidence(packets, raw_feature_df)
    if feature_df.empty:
        return _empty_result(
            "No supported TCP/UDP IP flows found in file",
            packet_count=evidence["packet_count"],
            evidence=evidence,
        )

    model, scaler, feature_columns, classes, device = load_detector()
    prepared = _prepare_features(feature_df, feature_columns)
    scaled = scaler.transform(prepared.values).astype(np.float32)
    input_diagnostics = _build_input_diagnostics(scaled, feature_columns)
    probabilities = _predict_probabilities(model, scaled, device)

    pred_indices = np.argmax(probabilities, axis=1)
    predictions = [classes[index] for index in pred_indices]
    attack_counts = {label: 0 for label in classes}
    attack_counts.update(Counter(predictions))
    total_flows = len(predictions)
    attack_percentages = {
        label: count / total_flows * 100 if total_flows else 0.0
        for label, count in attack_counts.items()
    }

    malicious_counts = {
        label: count for label, count in attack_counts.items()
        if label != "Normal"
    }
    malicious_total = sum(malicious_counts.values())
    malicious_ratio = malicious_total / total_flows if total_flows else 0.0
    threshold = float(os.getenv("TRANSFORMER_MALICIOUS_FLOW_THRESHOLD", "0.30"))

    if malicious_counts and malicious_ratio >= threshold:
        main_attack = max(malicious_counts.items(), key=lambda item: item[1])[0]
        status = f"检测到{main_attack}攻击（恶意流占比{malicious_ratio * 100:.1f}%）"
    else:
        main_attack = "Normal"
        status = "流量正常"

    mean_probabilities = probabilities.mean(axis=0)
    top_indices = np.argsort(mean_probabilities)[::-1][:3]
    topk = [
        {"label": classes[index], "score": float(mean_probabilities[index])}
        for index in top_indices
    ]
    main_index = classes.index(main_attack)
    confidence = float(mean_probabilities[main_index])

    prediction_details = []
    for row_index, (label, row_probs, pred_index) in enumerate(
        zip(predictions, probabilities, pred_indices)
    ):
        row_top_indices = np.argsort(row_probs)[::-1][:3]
        raw = raw_feature_df.iloc[row_index].to_dict()
        prediction_details.append({
            "flow_index": row_index,
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "src_port": int(raw.get("src_port", 0)),
            "dst_port": int(raw.get("dst_port", 0)),
            "protocol": raw.get("protocol"),
            "attack_type": label,
            "confidence": float(row_probs[pred_index]),
            "topk": [
                {"label": classes[index], "score": float(row_probs[index])}
                for index in row_top_indices
            ],
        })

    return {
        "status": status,
        "attack_type": main_attack,
        "confidence": confidence,
        "topk": topk,
        "total_packets": total_flows,
        "packet_count": evidence["packet_count"],
        "attack_distribution": attack_counts,
        "attack_percentages": attack_percentages,
        "protocol_distribution": evidence["protocol_counts"],
        "evidence": evidence,
        "prediction_details": prediction_details[:100],
        "feature_columns": feature_columns,
        "model_name": MODEL_NAME,
        "feature_type": FEATURE_TYPE,
        "detection_pipeline": DETECTION_PIPELINE,
        "device": str(device),
        "input_diagnostics": input_diagnostics,
    }
