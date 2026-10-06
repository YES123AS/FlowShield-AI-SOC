import json

from .llm_client import DeepSeekClient


def build_report_prompt(analysis_result):
    safe_input = {
        "事件标题": analysis_result.get("title"),
        "攻击类型": analysis_result.get("attack_type"),
        "风险分数": analysis_result.get("risk_score"),
        "风险等级": analysis_result.get("severity_label"),
        "事件摘要": analysis_result.get("summary"),
        "判断依据": analysis_result.get("judgement_basis"),
        "原因分析": analysis_result.get("cause_analysis"),
        "影响分析": analysis_result.get("impact_analysis"),
        "攻击链": analysis_result.get("attack_chain"),
        "处置建议": analysis_result.get("recommendations"),
        "历史关联": analysis_result.get("history"),
        "检测证据": analysis_result.get("evidence")
    }

    return f"""
请基于以下结构化安全检测结果，生成一份防御性安全事件分析报告。

要求：
1. 不要提供攻击执行步骤；
2. 不要提供漏洞利用代码；
3. 不要指导绕过安全防护；
4. 报告应面向管理员，内容清晰、专业、可执行；
5. 输出结构包括：事件概览、检测结论、判断依据、攻击链分析、影响分析、处置建议、后续加固建议。

结构化检测结果如下：
{json.dumps(safe_input, ensure_ascii=False, indent=2)}
"""


def generate_ai_report(analysis_result):
    prompt = build_report_prompt(analysis_result)
    client = DeepSeekClient()
    return client.generate_report(prompt)
