"""Export only PCAPs that pass the complete deployed Transformer prediction path."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from scapy.all import wrpcap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.search_model_matched_pcaps import build_packets
from utils.predict import predict
from utils.security.rule_engine import run_rule_engine


SOURCE = ROOT / "model_test_pcaps" / "search_results.json"
OUTPUT = ROOT / "model_verified_pcaps"
TARGETS = ["DDoS", "DoS", "Malware", "WebAttack"]


def export():
    results = json.loads(SOURCE.read_text(encoding="utf-8"))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for stale in OUTPUT.rglob("*.pcap"):
        stale.unlink()
    for stale_name in ("verification_results.csv", "verification_results.json"):
        stale = OUTPUT / stale_name
        if stale.exists():
            stale.unlink()
    rows = []

    for target in TARGETS:
        target_dir = OUTPUT / target
        target_dir.mkdir()
        accepted = 0
        seen = set()
        for candidate in results.get(target, []):
            config = candidate["config"]
            signature = json.dumps(config, sort_keys=True)
            if signature in seen:
                continue
            seen.add(signature)

            temporary = target_dir / f"_candidate_{accepted + 1:02d}.pcap"
            wrpcap(str(temporary), build_packets(config, seed=accepted + len(rows)))
            prediction = predict(str(temporary))
            if prediction["attack_type"] != target:
                temporary.unlink()
                continue

            accepted += 1
            final_path = target_dir / f"{target.lower()}_model_verified_{accepted:02d}.pcap"
            temporary.rename(final_path)
            rules = run_rule_engine(prediction.get("evidence", {}))
            rows.append({
                "expected_class": target,
                "file": str(final_path.relative_to(ROOT)),
                "model_prediction": prediction["attack_type"],
                "model_confidence": prediction["confidence"],
                "flow_count": prediction.get("total_packets"),
                "packet_count": prediction.get("packet_count"),
                "drift_warning": prediction.get("input_diagnostics", {}).get("warning"),
                "rule_hits": ",".join(hit["rule_id"] for hit in rules),
                "config": json.dumps(config, ensure_ascii=False, sort_keys=True),
            })
            if accepted == 3:
                break
        if accepted < 3:
            raise RuntimeError(f"{target} only produced {accepted} verified files")

    with (OUTPUT / "verification_results.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    (OUTPUT / "verification_results.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Exported {len(rows)} model-verified PCAPs to {OUTPUT}")


if __name__ == "__main__":
    export()
