import os


class DeepSeekConfigurationError(RuntimeError):
    pass


class DeepSeekAuthenticationError(RuntimeError):
    pass


class DeepSeekClient:
    """DeepSeek OpenAI-compatible client for defensive SOC reports."""

    def __init__(self):
        self.api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        self.base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip()
        self.model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro").strip()
        self.enabled = os.getenv("DEEPSEEK_ENABLE", "false").lower() == "true"
        self.client = None

        if not self.enabled:
            return
        if not self.api_key:
            raise DeepSeekConfigurationError("已开启 DeepSeek，但未配置 DEEPSEEK_API_KEY")
        if not self.api_key.startswith("sk-"):
            raise DeepSeekConfigurationError(
                "DEEPSEEK_API_KEY 格式不正确。请到 DeepSeek Platform 重新创建 API Key，"
                "复制以 sk- 开头的完整密钥后重启服务。"
            )

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise DeepSeekConfigurationError("已开启 DeepSeek，但未安装 openai SDK，请先安装 requirements.txt") from exc

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def generate_report(self, prompt):
        if not self.enabled:
            return ""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "你是一名安全运营中心 SOC 分析师。"
                            "你的任务是基于结构化检测结果生成防御性安全分析报告。"
                            "不要提供攻击执行步骤，不要提供利用代码，不要指导绕过防御。"
                            "输出内容应包括事件摘要、判断依据、影响分析、攻击链分析和处置建议。"
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                stream=False
            )
        except Exception as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code == 401 or exc.__class__.__name__ == "AuthenticationError":
                raise DeepSeekAuthenticationError(
                    "DeepSeek 认证失败：当前 DEEPSEEK_API_KEY 无效、已删除或复制不完整。"
                    "请在 DeepSeek Platform 重新创建 API Key，更新 .env 后重启服务。"
                ) from exc
            raise

        return response.choices[0].message.content
