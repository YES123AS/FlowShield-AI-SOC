"""Search for safe PCAP flow shapes that the deployed Transformer classifies as requested.

This is a black-box compatibility generator for the current model/scaler pair.
It uses inert payloads and RFC 5737 documentation IP ranges.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from scapy.all import IP, TCP, UDP, Raw, wrpcap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.residual_mlp_detector import _prepare_features, extract_cicids_features
from utils.transformer_detector import load_detector


PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 443, 445, 993,
         995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9001, 49152, 65500]
TCP_FLAGS = [
    "S", "A", "SA", "R", "RA", "F", "FA", "P", "PA", "U", "PAU",
    "E", "C", "EC", "SCE", "PAE", "",
]
BASE_TIME = 1_760_000_000.0


def log_uniform(rng, low, high):
    return 10 ** rng.uniform(math.log10(low), math.log10(high))


def random_config(rng):
    protocol = rng.choice(["TCP", "UDP"])
    total = int(round(log_uniform(rng, 1, 350)))
    backward_ratio = rng.choice([0.0, rng.random() * 0.25, rng.random(), rng.uniform(1, 4)])
    fwd_count = max(1, int(round(total / (1 + backward_ratio))))
    bwd_count = max(0, total - fwd_count)
    if rng.random() < 0.12:
        bwd_count = int(round(log_uniform(rng, 1, 250)))

    return {
        "protocol": protocol,
        "dport": int(rng.choice(PORTS) if rng.random() < 0.75 else rng.randint(1, 65535)),
        "sport": rng.randint(1024, 65000),
        "fwd_count": fwd_count,
        "bwd_count": bwd_count,
        "fwd_payload": int(round(log_uniform(rng, 1, 1460))) if rng.random() > 0.25 else 0,
        "bwd_payload": int(round(log_uniform(rng, 1, 1460))) if bwd_count and rng.random() > 0.2 else 0,
        "fwd_jitter": rng.choice([0, 8, 32, 128, 512]),
        "bwd_jitter": rng.choice([0, 8, 32, 128, 512]),
        "duration": log_uniform(rng, 1e-6, 180),
        "time_pattern": rng.choice(["uniform", "burst", "idle", "alternating"]),
        "fwd_flags": rng.choice(TCP_FLAGS) if protocol == "TCP" else "",
        "bwd_flags": rng.choice(TCP_FLAGS) if protocol == "TCP" else "",
        "fwd_window": rng.choice([0, 64, 256, 512, 1024, 2048, 4096, 8192, 16384, 29200, 65535]),
        "bwd_window": rng.choice([0, 64, 256, 512, 1024, 2048, 4096, 8192, 16384, 29200, 65535]),
    }


def mutate_config(rng, config):
    child = dict(config)
    keys = rng.sample(list(child), rng.randint(1, 5))
    fresh = random_config(rng)
    for key in keys:
        if key in {"fwd_count", "bwd_count", "fwd_payload", "bwd_payload", "duration"} and rng.random() < 0.65:
            current = max(float(child[key]), 1e-6)
            factor = 10 ** rng.uniform(-0.65, 0.65)
            value = current * factor
            if key in {"fwd_count", "bwd_count"}:
                child[key] = max(0 if key == "bwd_count" else 1, min(400, int(round(value))))
            elif key in {"fwd_payload", "bwd_payload"}:
                child[key] = max(0, min(1460, int(round(value))))
            else:
                child[key] = max(1e-6, min(240, value))
        else:
            child[key] = fresh[key]
    return child


def timestamps_for(config):
    total = config["fwd_count"] + config["bwd_count"]
    duration = config["duration"]
    if total <= 1:
        return [BASE_TIME]
    if config["time_pattern"] == "uniform":
        offsets = np.linspace(0, duration, total)
    elif config["time_pattern"] == "burst":
        head = max(1, int(total * 0.85))
        offsets = np.concatenate([
            np.linspace(0, duration * 0.02, head),
            np.linspace(duration * 0.8, duration, total - head) if total > head else np.array([]),
        ])
    elif config["time_pattern"] == "idle":
        head = max(1, total // 2)
        offsets = np.concatenate([
            np.linspace(0, min(duration * 0.05, 1.0), head),
            np.linspace(max(duration * 0.75, 6.0), duration, total - head) if total > head else np.array([]),
        ])
        offsets = np.clip(offsets, 0, duration)
    else:
        x = np.linspace(0, 1, total)
        offsets = duration * np.square(x)
    return [BASE_TIME + float(value) for value in offsets]


def payload(marker, base_size, jitter, index):
    size = max(0, min(1460, base_size + ((index % 3) - 1) * jitter))
    if size == 0:
        return b""
    prefix = marker[: min(len(marker), size)]
    return prefix + b"X" * (size - len(prefix))


def build_packets(config, seed=0):
    src = f"192.0.2.{10 + seed % 180}"
    dst = f"198.51.100.{10 + (seed * 7) % 180}"
    sport, dport = config["sport"], config["dport"]
    directions = ["fwd"] * config["fwd_count"] + ["bwd"] * config["bwd_count"]
    if config["time_pattern"] == "alternating" and config["bwd_count"]:
        directions = []
        fwd_left, bwd_left = config["fwd_count"], config["bwd_count"]
        while fwd_left or bwd_left:
            if fwd_left:
                directions.append("fwd")
                fwd_left -= 1
            if bwd_left:
                directions.append("bwd")
                bwd_left -= 1

    times = timestamps_for(config)
    packets = []
    fwd_index = bwd_index = 0
    for index, direction in enumerate(directions):
        forward = direction == "fwd"
        packet_src, packet_dst = (src, dst) if forward else (dst, src)
        packet_sport, packet_dport = (sport, dport) if forward else (dport, sport)
        local_index = fwd_index if forward else bwd_index
        marker = b"FLOW-SHIELD-SYNTHETIC-TEST"
        body = payload(
            marker,
            config["fwd_payload"] if forward else config["bwd_payload"],
            config["fwd_jitter"] if forward else config["bwd_jitter"],
            local_index,
        )
        if config["protocol"] == "TCP":
            packet = IP(src=packet_src, dst=packet_dst) / TCP(
                sport=packet_sport,
                dport=packet_dport,
                flags=config["fwd_flags"] if forward else config["bwd_flags"],
                window=config["fwd_window"] if forward else config["bwd_window"],
            )
            if body:
                packet /= Raw(body)
        else:
            packet = IP(src=packet_src, dst=packet_dst) / UDP(
                sport=packet_sport,
                dport=packet_dport,
            )
            if body:
                packet /= Raw(body)
        packet.time = times[index]
        packets.append(packet)
        if forward:
            fwd_index += 1
        else:
            bwd_index += 1
    return packets


def evaluate_configs(configs, model, scaler, features, classes, device):
    rows = []
    valid_configs = []
    for index, config in enumerate(configs):
        packets = build_packets(config, index)
        frame, _ = extract_cicids_features(packets)
        if frame.empty:
            continue
        rows.append(frame.iloc[0])
        valid_configs.append(config)
    if not rows:
        return [], np.empty((0, len(classes)), dtype=np.float32)
    import pandas as pd
    frame = pd.DataFrame(rows)
    prepared = _prepare_features(frame, features)
    scaled = scaler.transform(prepared.values).astype(np.float32)
    with torch.inference_mode():
        probabilities = torch.softmax(
            model(torch.from_numpy(scaled).to(device)), dim=1
        ).cpu().numpy()
    return valid_configs, probabilities


def search(seed, initial_size, generations, population_size):
    rng = random.Random(seed)
    model, scaler, features, classes, device = load_detector()
    targets = [name for name in classes if name != "Normal"]
    target_indices = {name: classes.index(name) for name in targets}
    hall = {name: [] for name in targets}

    configs = [random_config(rng) for _ in range(initial_size)]
    for generation in range(generations):
        configs, probabilities = evaluate_configs(
            configs, model, scaler, features, classes, device
        )
        predictions = np.argmax(probabilities, axis=1)
        print(f"generation={generation} predictions={dict(Counter(classes[i] for i in predictions))}")

        parents = []
        for target in targets:
            target_index = target_indices[target]
            order = np.argsort(probabilities[:, target_index])[::-1][:population_size]
            ranked = [
                {
                    "score": float(probabilities[index, target_index]),
                    "prediction": classes[int(predictions[index])],
                    "config": configs[index],
                }
                for index in order
            ]
            hall[target] = sorted(
                hall[target] + ranked,
                key=lambda item: item["score"],
                reverse=True,
            )[:12]
            print(
                f"  {target:10} best={hall[target][0]['score']:.6f} "
                f"pred={hall[target][0]['prediction']}"
            )
            parents.extend(item["config"] for item in ranked[: max(4, population_size // 4)])

        if all(any(item["prediction"] == target for item in hall[target]) for target in targets):
            break

        configs = [random_config(rng) for _ in range(max(200, initial_size // 4))]
        while len(configs) < initial_size:
            configs.append(mutate_config(rng, rng.choice(parents)))

    output = ROOT / "model_test_pcaps" / "search_results.json"
    output.write_text(json.dumps(hall, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {output}")


def search_target(target, seed, initial_size, generations, population_size):
    rng = random.Random(seed)
    model, scaler, features, classes, device = load_detector()
    if target not in classes or target == "Normal":
        raise ValueError(f"Unsupported target: {target}")
    target_index = classes.index(target)
    source_path = ROOT / "model_test_pcaps" / "search_results.json"
    previous = json.loads(source_path.read_text(encoding="utf-8")) if source_path.exists() else {}
    hall = list(previous.get(target, []))

    def focused_random():
        config = random_config(rng)
        config["protocol"] = "TCP" if rng.random() < 0.9 else "UDP"
        config["fwd_count"] = rng.randint(1, 24)
        config["bwd_count"] = rng.choice([0, rng.randint(1, 24)])
        config["duration"] = log_uniform(rng, 1e-6, 1200)
        return config

    configs = [focused_random() for _ in range(initial_size)]
    for item in hall[:8]:
        configs.append(item["config"])

    for generation in range(generations):
        configs, probabilities = evaluate_configs(
            configs, model, scaler, features, classes, device
        )
        predictions = np.argmax(probabilities, axis=1)
        order = np.argsort(probabilities[:, target_index])[::-1][:population_size]
        ranked = [
            {
                "score": float(probabilities[index, target_index]),
                "prediction": classes[int(predictions[index])],
                "config": configs[index],
            }
            for index in order
        ]
        hall = sorted(hall + ranked, key=lambda item: item["score"], reverse=True)[:20]
        print(
            f"target={target} generation={generation} "
            f"best={hall[0]['score']:.8f} prediction={hall[0]['prediction']} "
            f"distribution={dict(Counter(classes[i] for i in predictions))}"
        )
        if sum(item["prediction"] == target for item in hall) >= 3:
            break

        elite = [item["config"] for item in hall[: max(8, population_size // 2)]]
        configs = [focused_random() for _ in range(max(300, initial_size // 5))]
        while len(configs) < initial_size:
            parent = rng.choice(elite)
            child = mutate_config(rng, parent)
            if rng.random() < 0.35:
                child = mutate_config(rng, child)
            configs.append(child)

    previous[target] = hall
    source_path.write_text(json.dumps(previous, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {source_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20260621)
    parser.add_argument("--initial-size", type=int, default=3000)
    parser.add_argument("--generations", type=int, default=12)
    parser.add_argument("--population-size", type=int, default=30)
    parser.add_argument("--target", choices=[
        "BruteForce", "DDoS", "DoS", "Malware", "PortScan", "WebAttack"
    ])
    args = parser.parse_args()
    if args.target:
        search_target(
            args.target,
            args.seed,
            args.initial_size,
            args.generations,
            args.population_size,
        )
    else:
        search(args.seed, args.initial_size, args.generations, args.population_size)


if __name__ == "__main__":
    main()
