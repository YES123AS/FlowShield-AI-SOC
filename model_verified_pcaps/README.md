# 经当前 Transformer 实际验收的 PCAP

本目录中的文件必须通过项目完整的 `utils.predict.predict()` 调用，且
`attack_type` 与目录名称一致，才会被导出。

当前可以稳定生成并通过验收的恶意类别：

- `DDoS`
- `DoS`
- `Malware`
- `WebAttack`

每类 3 个文件。逐文件置信度见 `verification_results.csv`。

`BruteForce` 和 `PortScan` 未放入本目录，因为当前权重与 Scapy 特征提取组合
无法在本次合法参数搜索中使它们战胜 `Normal`。把规则引擎命中的 PortScan
称为“模型识别成功”是不准确的。

这些文件是模型回归测试向量，用于验证当前部署模型的输出，不等同于真实攻击
流量。所有 IP 均使用文档保留网段，载荷无攻击功能。
