import json
import os


THREAT_INTEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "threat_intel.json"
)


def load_threat_intel():
    if not os.path.exists(THREAT_INTEL_PATH):
        return {}
    with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def check_ip_reputation(ip_list):
    intel = load_threat_intel()
    hits = []
    seen = set()
    for ip in ip_list:
        if ip in seen:
            continue
        seen.add(ip)
        if ip in intel:
            item = intel[ip]
            hits.append({
                "ip": ip,
                "risk": item.get("risk", "unknown"),
                "type": item.get("type", "unknown"),
                "source": item.get("source", "local"),
                "description": item.get("description", "")
            })
    return hits
