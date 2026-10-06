# 最终 PCAP 联调测试集

共 21 个安全合成 PCAP：

- `DDoS`、`DoS`、`Malware`、`WebAttack`：各 3 个，当前 Transformer 实际输出与类别一致。
- `PortScan`：3 个，Transformer 可能输出 `Normal`，由端口扫描规则融合为 `PortScan`。
- `BruteForce`：3 个，Transformer 可能输出 `Normal`，由认证端口重复连接规则融合为 `BruteForce`。
- `Normal`：3 个正常对照。

`verification_results.csv` 同时记录模型原始输出和模型、规则融合后的最终输出。
这套文件用于测试上传检测、风险评分、安全事件和 Dashboard，不包含真实攻击载荷。
