"""Build the final safe PCAP suite and verify model + rule fusion output."""

from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blueprints.qa import build_enhanced_detection_result
from utils.predict import predict


OUTPUT = ROOT / "final_pcap_test_suite"
SOURCES = {
    "DDoS": ROOT / "model_verified_pcaps" / "DDoS",
    "DoS": ROOT / "model_verified_pcaps" / "DoS",
    "Malware": ROOT / "model_verified_pcaps" / "Malware",
    "WebAttack": ROOT / "model_verified_pcaps" / "WebAttack",
    "PortScan": ROOT / "model_test_pcaps" / "PortScan",
    "BruteForce": ROOT / "model_test_pcaps" / "BruteForce",
    "Normal": ROOT / "model_test_pcaps" / "Normal",
}


def build():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT.rglob("*.pcap"):
        old.unlink()

    rows = []
    for expected, source_dir in SOURCES.items():
        destination_dir = OUTPUT / expected
        destination_dir.mkdir(exist_ok=True)
        source_files = sorted(source_dir.glob("*.pcap"))[:3]
        if len(source_files) != 3:
            raise RuntimeError(f"{expected}: expected 3 source PCAPs, got {len(source_files)}")

        for index, source in enumerate(source_files, start=1):
            destination = destination_dir / f"{expected.lower()}_test_{index:02d}.pcap"
            shutil.copy2(source, destination)

            model_result = predict(str(destination))
            enhanced, _ = build_enhanced_detection_result(model_result)
            rows.append({
                "expected_class": expected,
                "file": str(destination.relative_to(ROOT)),
                "model_prediction": model_result["attack_type"],
                "model_confidence": model_result.get("confidence"),
                "final_fused_prediction": enhanced["attack_type"],
                "risk_score": enhanced["risk_score"],
                "severity": enhanced["severity"],
                "rule_ids": ",".join(
                    item["rule_id"] for item in enhanced.get("rule_hits", [])
                ),
                "passed": enhanced["attack_type"] == expected,
            })

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

    failed = [row for row in rows if not row["passed"]]
    for row in rows:
        print(
            f"{row['expected_class']:10} model={row['model_prediction']:10} "
            f"fused={row['final_fused_prediction']:10} "
            f"risk={row['risk_score']:3} passed={row['passed']}"
        )
    if failed:
        raise RuntimeError(f"{len(failed)} PCAPs failed fused verification")
    print(f"Built and verified {len(rows)} PCAPs in {OUTPUT}")


if __name__ == "__main__":
    build()
