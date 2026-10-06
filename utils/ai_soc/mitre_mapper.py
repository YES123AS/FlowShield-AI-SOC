ATTACK_CHAIN_MAP = {
    "Normal": {
        "phase": "正常活动",
        "description": "未发现明显攻击链。",
        "steps": ["持续监控", "基线维护"]
    },
    "PortScan": {
        "phase": "侦察 / 探测阶段",
        "description": "侦察探测 -> 发现开放端口 -> 识别服务类型 -> 后续可能进行漏洞利用或暴力破解。",
        "steps": ["侦察探测", "发现开放端口", "识别服务类型", "后续漏洞利用或暴力破解"]
    },
    "BruteForce": {
        "phase": "凭证访问阶段",
        "description": "凭证访问 -> 密码猜测 -> 账号失陷 -> 横向移动或数据窃取。",
        "steps": ["凭证访问", "密码猜测", "账号失陷", "横向移动或数据窃取"]
    },
    "DDoS": {
        "phase": "影响阶段",
        "description": "资源消耗 -> 服务拥塞 -> 业务不可用。",
        "steps": ["资源消耗", "服务拥塞", "业务不可用"]
    },
    "Malware": {
        "phase": "命令控制 / 持久化阶段",
        "description": "主机感染 -> C2 通信 -> 远程控制 -> 横向移动或数据窃取。",
        "steps": ["主机感染", "C2 通信", "远程控制", "横向移动或数据窃取"]
    },
    "DataExfiltration": {
        "phase": "数据收集 / 外泄阶段",
        "description": "数据收集 -> 数据打包 -> 外联传输 -> 数据泄露。",
        "steps": ["数据收集", "数据打包", "外联传输", "数据泄露"]
    }
}


def map_attack_chain(attack_type):
    return ATTACK_CHAIN_MAP.get(attack_type, {
        "phase": "异常行为阶段",
        "description": "异常发现 -> 人工复核 -> 处置加固。",
        "steps": ["异常发现", "人工复核", "处置加固"]
    })
