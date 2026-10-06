import os


def _backend_name():
    return os.getenv("DETECTOR_BACKEND", "transformer").strip().lower()


def detector_status(load_model=False):
    backend = _backend_name()
    if backend in {"transformer", "tabular_transformer"}:
        from utils.transformer_detector import detector_status as get_status
    elif backend in {"residual_mlp", "mlp"}:
        from utils.residual_mlp_detector import load_detector

        status = {
            "backend": "residual_mlp",
            "model_name": "Residual MLP",
            "ready": True,
        }
        if load_model:
            _, _, features, classes, device = load_detector()
            status.update({
                "loaded": True,
                "device": str(device),
                "num_features": len(features),
                "classes": classes,
            })
        return status
    else:
        raise ValueError(f"不支持的 DETECTOR_BACKEND：{backend}")
    return get_status(load_model=load_model)


def predict(save_path):
    backend = _backend_name()
    if backend in {"transformer", "tabular_transformer"}:
        from utils.transformer_detector import predict_pcap
    elif backend in {"residual_mlp", "mlp"}:
        from utils.residual_mlp_detector import predict_pcap
    else:
        raise ValueError(f"不支持的 DETECTOR_BACKEND：{backend}")
    return predict_pcap(save_path)


if __name__ == "__main__":
    result = predict("test.pcap")
    print("Detection Result:")
    print(result)
