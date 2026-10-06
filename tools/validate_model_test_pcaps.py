"""Run the current detector and rule engine against generated test PCAPs."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.predict import predict
from utils.security.rule_engine import run_rule_engine


TEST_DIR = ROOT / "model_test_pcaps"


def validate():
    manifest_path = TEST_DIR / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = []

    for item in manifest:
        path = ROOT / item["relative_path"]
        result = predict(str(path))
        rule_hits = run_rule_engine(result.get("evidence", {}))
        predicted = result.get("attack_type", "Unknown")
        rows.append({
            **item,
            "model_prediction": predicted,
            "model_confidence": result.get("confidence"),
            "semantic_match": predicted == item["expected_scenario"],
            "status": result.get("status"),
            "flow_count": result.get("evidence", {}).get("flow_count", 0),
            "drift_warning": result.get("input_diagnostics", {}).get("warning"),
            "rule_attack_types": ",".join(sorted({
                hit["attack_type"] for hit in rule_hits
            })),
            "rule_ids": ",".join(hit["rule_id"] for hit in rule_hits),
        })
        print(
            f"{item['expected_scenario']:10} v{item['variant']} -> "
            f"{predicted:10} rules={rows[-1]['rule_attack_types'] or '-'}"
        )

    csv_path = TEST_DIR / "validation_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    json_path = TEST_DIR / "validation_results.json"
    json_path.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {csv_path}")


if __name__ == "__main__":
    validate()
