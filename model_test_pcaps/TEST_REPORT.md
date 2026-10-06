# 当前模型测试报告

## 测试集

- 当前 Transformer 类别：`Normal`、`DDoS`、`DoS`、`PortScan`、`BruteForce`、`WebAttack`、`Malware`
- 每个类别 3 个 PCAP，共 21 个文件
- 其中恶意场景 18 个，正常对照 3 个
- 地址只使用文档保留网段，载荷为无功能测试标记

## 实测结论

使用当前 `models/transformer_best.pt`、`models/scaler.joblib` 和
`utils/residual_mlp_detector.py` 中的 Scapy 特征提取逻辑执行验证：

| 预期场景 | 样本数 | Transformer 主输出 | 规则引擎结果 |
| --- | ---: | --- | --- |
| Normal | 3 | 3 个均为 Normal | 无命中 |
| DDoS | 3 | 3 个均为 Normal | 3 个均命中 DDoS |
| DoS | 3 | 3 个均为 Normal | 3 个均因高包速率命中 DDoS 规则 |
| PortScan | 3 | 3 个均为 Normal | 3 个均命中 PortScan |
| BruteForce | 3 | 3 个均为 Normal | 无对应规则 |
| WebAttack | 3 | 3 个均为 Normal | 无对应规则 |
| Malware | 3 | 3 个均为 Normal | 无对应规则 |

详细逐文件结果见 `validation_results.csv` 或 `validation_results.json`。

## 解释

这些 PCAP 已经能够测试完整上传、Scapy 解析、Flow 聚合、70 维特征、
Transformer 推理和规则融合链路。但当前 Transformer 对所有合成样本均输出
`Normal`，因此不能把这批结果解释为六类模型测试已经通过。

项目训练特征来自 CICFlowMeter 风格数据，而线上使用 Scapy 近似生成特征。
两者在包长、Header Length、方向、Active/Idle 等定义上可能存在明显偏差。
本次结果与项目中的输入漂移风险说明一致。建议下一步使用训练模型时完全相同
版本的 CICFlowMeter 生成验证特征，并用带真实标签的独立验证集建立混淆矩阵。

## 复测

```powershell
python tools\generate_model_test_pcaps.py
python tools\validate_model_test_pcaps.py
```
