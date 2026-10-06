ATTACK_EXPLANATIONS = {
    "Normal": {
        "name": "正常流量",
        "summary": "当前流量未发现明显攻击特征。",
        "reasons": [
            "流量行为与正常业务访问模式较为接近。",
            "未检测到明显的扫描、爆破、数据外传或恶意软件通信特征。"
        ]
    },
    "DDoS": {
        "name": "分布式拒绝服务攻击",
        "summary": "检测到疑似 DDoS 攻击，攻击者可能通过大量请求消耗目标服务资源。",
        "reasons": [
            "短时间内出现大量数据包或请求。",
            "目标 IP 或目标端口高度集中。",
            "流量速率明显高于正常访问模式。",
            "可能导致服务器带宽、CPU、连接数等资源耗尽。"
        ]
    },
    "PortScan": {
        "name": "端口扫描",
        "summary": "检测到疑似端口扫描行为，攻击者可能正在探测目标主机开放服务。",
        "reasons": [
            "同一来源可能访问了多个目标端口。",
            "连接行为具有探测性质。",
            "部分连接持续时间较短或未完成完整通信。",
            "该行为通常出现在漏洞利用或暴力破解之前。"
        ]
    },
    "BruteForce": {
        "name": "暴力破解",
        "summary": "检测到疑似暴力破解行为，攻击者可能正在尝试猜测账号密码。",
        "reasons": [
            "短时间内出现大量重复访问或认证尝试。",
            "访问目标可能集中在登录、SSH、FTP、数据库等服务。",
            "请求模式高度重复。",
            "如果攻击成功，可能导致账号失陷或权限泄露。"
        ]
    },
    "DataExfiltration": {
        "name": "数据外泄",
        "summary": "检测到疑似数据外泄行为，内部数据可能正在被异常传输到外部地址。",
        "reasons": [
            "出站流量可能异常增大。",
            "存在向外部地址传输大量数据的风险。",
            "通信目标、通信时间或协议可能偏离正常业务模式。",
            "该类事件可能造成敏感数据泄露和合规风险。"
        ]
    },
    "Malware": {
        "name": "恶意软件通信",
        "summary": "检测到疑似恶意软件通信，主机可能存在感染、远控或异常外联行为。",
        "reasons": [
            "存在可疑远程通信行为。",
            "可能出现周期性回连或异常端口通信。",
            "可能涉及恶意载荷下载、C2 通信或信息回传。",
            "该类事件可能意味着主机已经被入侵。"
        ]
    }
}


def explain_attack(attack_type, extra_evidence=None):
    info = ATTACK_EXPLANATIONS.get(attack_type, {
        "name": attack_type,
        "summary": "检测到未知类型异常流量。",
        "reasons": ["该攻击类型暂无内置解释规则。"]
    })
    result = {
        "attack_name": info["name"],
        "summary": info["summary"],
        "reasons": list(info["reasons"])
    }
    if extra_evidence:
        result["reasons"].extend(extra_evidence)
    return result
