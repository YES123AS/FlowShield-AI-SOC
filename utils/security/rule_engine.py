IMPORTANT_PORTS = {21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 6379, 8080}
AUTH_PORTS = {21, 22, 23, 3389}


def run_rule_engine(features):
    hits = []

    packet_count = features.get("packet_count", 0) or 0
    unique_dst_ports = features.get("unique_dst_ports", 0) or 0
    bytes_out = features.get("bytes_out", 0) or 0
    dst_ports = set(features.get("dst_ports", []))
    dst_port_counts = {
        int(port): int(count)
        for port, count in (features.get("dst_port_counts", {}) or {}).items()
    }
    duration = features.get("duration", 0) or 0

    if unique_dst_ports >= 20:
        hits.append({
            "rule_id": "RULE_PORTSCAN_001",
            "name": "短时间访问大量目标端口",
            "attack_type": "PortScan",
            "severity": "medium",
            "description": "检测到大量不同目标端口访问行为，可能存在端口扫描。"
        })

    if duration > 0:
        packet_rate = packet_count / duration
        if packet_count >= 200 and packet_rate >= 500:
            hits.append({
                "rule_id": "RULE_DDOS_001",
                "name": "短时间高包速率",
                "attack_type": "DDoS",
                "severity": "high",
                "description": "检测到单位时间内数据包数量异常升高，可能存在 DDoS 攻击。"
            })

    matched_ports = dst_ports.intersection(IMPORTANT_PORTS)
    if len(matched_ports) >= 3:
        hits.append({
            "rule_id": "RULE_SENSITIVE_PORT_001",
            "name": "访问多个敏感端口",
            "attack_type": "PortScan",
            "severity": "medium",
            "description": "检测到访问多个敏感端口：{}。".format(sorted(list(matched_ports)))
        })

    repeated_auth_ports = {
        port: count
        for port, count in dst_port_counts.items()
        if port in AUTH_PORTS and count >= 20
    }
    if repeated_auth_ports:
        hits.append({
            "rule_id": "RULE_BRUTEFORCE_001",
            "name": "认证服务短时间重复连接",
            "attack_type": "BruteForce",
            "severity": "high",
            "description": "检测到认证端口出现大量独立连接尝试：{}。".format(
                repeated_auth_ports
            )
        })

    if bytes_out >= 50 * 1024 * 1024:
        hits.append({
            "rule_id": "RULE_EXFIL_001",
            "name": "异常大出站流量",
            "attack_type": "DataExfiltration",
            "severity": "critical",
            "description": "检测到异常大的出站数据传输，可能存在数据外泄风险。"
        })

    return hits
