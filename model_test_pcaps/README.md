# FlowShield 合成 PCAP 测试集

此目录由 `tools/generate_model_test_pcaps.py` 生成，覆盖当前 Transformer 的六种恶意类别，并包含正常流量对照组。每类 3 个变体。

所有源/目标地址均来自 RFC 5737 文档保留网段 `192.0.2.0/24` 与 `198.51.100.0/24`。载荷仅为无功能的测试标记，不包含真实漏洞利用、口令或恶意程序。

注意：目录名代表测试场景的“预期语义”，模型输出仍取决于当前权重与 Scapy 特征近似。请结合 `validation_results.csv` 查看本次实际推理结果。

重新生成：

```powershell
python tools\generate_model_test_pcaps.py
```

单文件测试：

```powershell
python -c "from utils.predict import predict; print(predict(r'model_test_pcaps\DDoS\ddos_01.pcap'))"
```
