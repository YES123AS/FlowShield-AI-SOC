"""Generate safe, synthetic PCAPs for FlowShield model validation.

The packets use documentation-only IP ranges and inert marker payloads. They
simulate traffic *shapes* rather than carrying functional exploit content.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from scapy.all import IP, TCP, UDP, Raw, wrpcap


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "model_test_pcaps"
BASE_TIME = 1_750_000_000.0


def tcp_packet(src, dst, sport, dport, flags, timestamp, payload=b"", window=8192):
    packet = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        window=window,
    )
    if payload:
        packet /= Raw(payload)
    packet.time = timestamp
    return packet


def udp_packet(src, dst, sport, dport, timestamp, payload=b"FLOW-SHIELD-TEST"):
    packet = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
    packet.time = timestamp
    return packet


def normal_web(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{10 + variant}", "198.51.100.20"
    sport = 40000 + variant
    packets.extend([
        tcp_packet(src, dst, sport, 443, "S", t),
        tcp_packet(dst, src, 443, sport, "SA", t + 0.025),
        tcp_packet(src, dst, sport, 443, "A", t + 0.040),
    ])
    for index in range(6 + variant):
        payload = b"NORMAL-REQUEST-" + bytes([65 + index]) * (80 + variant * 20)
        packets.append(tcp_packet(src, dst, sport, 443, "PA", t + 0.1 + index * 0.08, payload))
        response = b"NORMAL-RESPONSE-" + bytes([97 + index]) * (350 + variant * 80)
        packets.append(tcp_packet(dst, src, 443, sport, "PA", t + 0.14 + index * 0.08, response))
    packets.extend([
        tcp_packet(src, dst, sport, 443, "FA", t + 1.0),
        tcp_packet(dst, src, 443, sport, "FA", t + 1.03),
    ])
    return packets


def ddos(variant):
    packets = []
    t = BASE_TIME
    dst = "198.51.100.50"
    sources = 18 + variant * 8
    bursts = 12 + variant * 8
    for source_index in range(sources):
        src = f"192.0.2.{20 + source_index}"
        sport = 20000 + source_index
        for index in range(bursts):
            packets.append(tcp_packet(
                src, dst, sport, 80, "S",
                t + source_index * 0.00001 + index * (0.0015 - variant * 0.0003),
                window=1024,
            ))
    return packets


def dos(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{80 + variant}", "198.51.100.60"
    sport = 30000 + variant
    count = 350 + variant * 250
    interval = 0.0012 - variant * 0.00025
    flags = ["S", "A", "PA"][variant - 1]
    payload = b"" if variant == 1 else b"LOAD" * (8 * variant)
    for index in range(count):
        packets.append(tcp_packet(
            src, dst, sport, 8080, flags, t + index * interval, payload, window=2048
        ))
    return packets


def port_scan(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{100 + variant}", "198.51.100.70"
    if variant == 1:
        ports = list(range(1, 81))
    elif variant == 2:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080]
        ports += list(range(9000, 9040))
    else:
        ports = list(range(20000, 20120))
    for index, dport in enumerate(ports):
        sport = 35000 + index
        packets.append(tcp_packet(src, dst, sport, dport, "S", t + index * 0.003))
        if variant == 2 and index % 3 == 0:
            packets.append(tcp_packet(dst, src, dport, sport, "RA", t + index * 0.003 + 0.001))
    return packets


def brute_force(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{120 + variant}", "198.51.100.80"
    dport = [21, 22, 3389][variant - 1]
    attempts = 35 + variant * 15
    for index in range(attempts):
        sport = 41000 + index
        start = t + index * (0.055 - variant * 0.008)
        marker = f"AUTH-TEST-ATTEMPT-{index:03d}".encode()
        packets.extend([
            tcp_packet(src, dst, sport, dport, "S", start, window=4096),
            tcp_packet(dst, src, dport, sport, "SA", start + 0.006, window=4096),
            tcp_packet(src, dst, sport, dport, "PA", start + 0.012, marker, window=4096),
            tcp_packet(dst, src, dport, sport, "PA", start + 0.018, b"AUTH-REJECTED", window=4096),
            tcp_packet(src, dst, sport, dport, "R", start + 0.023, window=4096),
        ])
    return packets


def web_attack(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{140 + variant}", "198.51.100.90"
    flows = 18 + variant * 10
    request_size = [220, 900, 2400][variant - 1]
    response_size = [120, 300, 80][variant - 1]
    for index in range(flows):
        sport = 45000 + index
        start = t + index * 0.025
        # Inert labels only; no executable SQL/XSS/exploit strings are included.
        request = b"POST /synthetic-test HTTP/1.1\r\nX-Test: WEB-ANOMALY\r\n\r\n"
        request += b"Q" * request_size
        response = b"HTTP/1.1 403 Forbidden\r\n\r\n" + b"R" * response_size
        packets.extend([
            tcp_packet(src, dst, sport, 80, "S", start, window=16384),
            tcp_packet(dst, src, 80, sport, "SA", start + 0.004, window=16384),
            tcp_packet(src, dst, sport, 80, "A", start + 0.007, window=16384),
            tcp_packet(src, dst, sport, 80, "PA", start + 0.010, request, window=16384),
            tcp_packet(dst, src, 80, sport, "PA", start + 0.014, response, window=16384),
            tcp_packet(dst, src, 80, sport, "FA", start + 0.018, window=16384),
        ])
    return packets


def malware(variant):
    packets = []
    t = BASE_TIME
    src, dst = f"192.0.2.{160 + variant}", f"198.51.100.{100 + variant}"
    if variant == 1:
        for index in range(20):
            packets.append(udp_packet(
                src, dst, 51000, 5353, t + index * 8.0,
                b"BEACON-TEST-" + bytes([65 + index % 20]) * 24,
            ))
            packets.append(udp_packet(
                dst, src, 5353, 51000, t + index * 8.0 + 0.08, b"ACK-TEST"
            ))
    elif variant == 2:
        for index in range(24):
            payload = b"HEARTBEAT-" + bytes([65 + index % 20]) * (40 + index % 4 * 30)
            packets.append(tcp_packet(
                src, dst, 52000, 8443, "PA", t + index * 6.5, payload, window=512
            ))
            if index % 3 == 0:
                packets.append(tcp_packet(
                    dst, src, 8443, 52000, "A", t + index * 6.5 + 0.12, window=512
                ))
    else:
        for index in range(30):
            dport = 9001 + index % 3
            payload = b"CONTROL-CHANNEL-TEST-" + bytes([97 + index % 20]) * 70
            packets.append(tcp_packet(
                src, dst, 53000 + dport, dport, "PA",
                t + index * 3.2, payload, window=256
            ))
    return packets


SCENARIOS = {
    "Normal": normal_web,
    "DDoS": ddos,
    "DoS": dos,
    "PortScan": port_scan,
    "BruteForce": brute_force,
    "WebAttack": web_attack,
    "Malware": malware,
}


def generate():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest = []
    for expected, builder in SCENARIOS.items():
        category_dir = OUTPUT_DIR / expected
        category_dir.mkdir()
        for variant in range(1, 4):
            packets = builder(variant)
            filename = f"{expected.lower()}_{variant:02d}.pcap"
            path = category_dir / filename
            wrpcap(str(path), packets)
            manifest.append({
                "expected_scenario": expected,
                "variant": variant,
                "relative_path": str(path.relative_to(ROOT)),
                "packet_count": len(packets),
                "safety": "synthetic/inert/documentation IP ranges",
            })

    with (OUTPUT_DIR / "manifest.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=manifest[0].keys())
        writer.writeheader()
        writer.writerows(manifest)
    with (OUTPUT_DIR / "manifest.json").open("w", encoding="utf-8") as file:
        json.dump(manifest, file, ensure_ascii=False, indent=2)

    print(f"Generated {len(manifest)} PCAP files in {OUTPUT_DIR}")


if __name__ == "__main__":
    generate()
