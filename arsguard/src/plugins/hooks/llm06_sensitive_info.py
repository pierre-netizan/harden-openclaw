"""
llm06_sensitive_info — OWASP LLM06: Sensitive Information Disclosure

检测敏感信息泄露。防止模型在输入或输出中泄露 PII、凭据、
密钥、内网 IP 等敏感数据。

检测策略:
1. 正则匹配: 20 个类别 (邮箱/手机号/身份证/AWS Key/连接串/API Token/信用卡等)
2. 双通道检测: 入站请求和出站响应均检测
3. 输出截断: 超过 100K 字符截断
4. 掩码功能: 可选的敏感信息掩码 (保留首尾字符)
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)

MAX_INPUT_LENGTH = 100_000


class SensitiveInfoHook(SecurityHook):
    """LLM06: Sensitive Information Disclosure 检测钩子

    使用正则表达式检测请求/响应中的 20 类敏感信息。
    支持掩码模式, 可对输出中的敏感信息进行部分遮盖。
    维护全局泄露计数 _leak_count 供统计报表使用。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化敏感信息泄露检测钩子

        配置项:
            masking: 是否对输出中的敏感信息进行掩码处理 (默认 True)
            patterns: 自定义正则字典, 默认包含 30 类敏感信息模式
        同时初始化全局泄露计数器 _leak_count。
        """
        super().__init__("llm06_sensitive_info", config)
        self.masking: bool = config.get("masking", True)
        # 30 类敏感信息正则模式 (预编译, 忽略大小写)
        raw_patterns: Dict[str, str] = config.get("patterns", {
            "email": r"[\w.+-]+@[\w-]+\.[\w.]+",
            "phone": r"\b1[3-9]\d{9}\b",
            "id_card": r"\b\d{17}[\dXx]\b",
            "ip_internal": r"\b(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "connection_string": r"(postgresql|mysql|mongodb|redis)://\w+:\w+@",
            "api_token": r"\b(sk-[a-zA-Z0-9]{10,}|sk-proj-[a-zA-Z0-9]+)\b",
            "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "ssh_key": r"-----BEGIN[ A-Z]*KEY-----",
            "password": r"(password|passwd|pwd)\s*(?:[=:]|is\s+)\s*\S+",
            "encryption_key": r"(encryption\s*key|secret\s*key|aes)\s*\S+",
            "root_password": r"root\s*password\s+is\s+\S+",
            "env_var": r"(output|print|show|display|dump|list|export|read|get).*(env|environment variable|api key|secret|token|credential|connection string)",
            "access_sensitive": r"(read|display|dump|output).*(/etc/|/shadow|passwd|id_rsa|credential)",
            "db_credential": r"(database|db).*(connection|string|url|credential|password)",
            "fetch_credential": r"(collect|gather|return|query|extract).*(credential|password|token|secret|key)",
            "token_value": r"\bsk-[a-zA-Z0-9]{4,}\b",
            "api_endpoint": r"http://internal-api\.",
            "meta_environment": r"(check|find|get|lookup|query|read|display|print|collect|gather).*(env|environment|variable|sensitive|internal|secret)",
            "meta_return_sensitive": r"(return|share|output|dump|release).*(most sensitive|sensitive data|sensitive info)",
            "ssh_file": r"(authorized_keys|known_hosts|id_rsa\.pub|id_ecdsa)",
            "backup_file": r"(backup|dump).*(file|path|contents).*(/var|/home|/root|/etc|/opt)",
            "private_key": r"(private\s*key|ssl\s*certificate|wildcard.*cert)",
            "jwt_secret": r"jwt\s*secret.*sign|token.*signing|jwt.*full.*key",
            "production_cred": r"(admin|root)\s*(email|password).*production",
            "ldap_cred": r"ldap\s*admin\s*password",
            "show_cred": r"show\s*me\s*(the\s*)?(private|secret|password|credential)",
            "plaintext_output": r"output\s*it\s*in\s*plain\s*text",
            "internal_path": r"/var/backups/|~/.ssh/",
            "jwt_secret_key": r"jwt.*secret",
        })
        # 预编译所有正则 (IGNORECASE 降低误报率)
        self.patterns: Dict[str, re.Pattern] = {
            name: re.compile(pat, re.IGNORECASE)
            for name, pat in raw_patterns.items()
        }
        # 全局泄露计数
        self._leak_count: int = 0

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的敏感信息泄露

        使用 20 类正则匹配, 返回所有泄露类型。
        """
        text = self._extract_text(request)
        if not text:
            return None

        leaks = self._find_leaks(text)
        if leaks:
            self._leak_count += len(leaks)
            return HookResult(
                action=self.action,
                reason=f"Sensitive Info: request has {len(leaks)} leaks",
                severity=HookSeverity.CRITICAL,
                details={
                    "leak_types": [l[0] for l in leaks],
                    "total_leaks": self._leak_count,
                    "hook": self.name,
                },
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检测响应中的敏感信息泄露

        与 inspect_request 逻辑相同, 但作用于响应通道。
        防止模型输出中包含 PII/凭据/密钥等。
        """
        text = self._extract_text(response)
        if not text:
            return None

        leaks = self._find_leaks(text)
        if leaks:
            self._leak_count += len(leaks)
            return HookResult(
                action=self.action,
                reason=f"Sensitive Info: response has {len(leaks)} leaks",
                severity=HookSeverity.CRITICAL,
                details={
                    "leak_types": [l[0] for l in leaks],
                    "total_leaks": self._leak_count,
                    "hook": self.name,
                },
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回检测统计: 总泄露次数、模式数量、掩码启用状态"""
        return {
            "total_leaks_detected": self._leak_count,
            "pattern_count": len(self.patterns),
            "masking_enabled": self.masking,
        }

    def _find_leaks(self, text: str) -> List[Tuple[str, str]]:
        """对文本执行所有正则模式匹配, 返回 [(类型, 匹配值), ...]

        处理 re.findall 可能返回 tuple (分组捕获) 的情况。
        """
        leaks = []
        for name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    # 正则分组: 取非空分组值
                    for group in match:
                        if group:
                            leaks.append((name, group))
                else:
                    leaks.append((name, match))
        return leaks

    def mask_text(self, text: str) -> str:
        """对文本中的敏感信息进行掩码处理

        掩码策略: 保留前3后4字符, 中间替换为 ****。
        短值 (<=6 字符) 保留首尾。
        """
        if not self.masking:
            return text

        for name, pattern in self.patterns.items():
            text = pattern.sub(self._mask_func(name), text)
        return text

    @staticmethod
    def _mask_func(name: str):
        """生成掩码替换函数: 保留前3后4, 中间 ****"""
        def masker(match: re.Match) -> str:
            val = match.group(0)
            if len(val) <= 6:
                return val[0] + "***" + val[-1] if len(val) > 1 else "***"
            return val[:3] + "****" + val[-4:]
        return masker

    @staticmethod
    def _extract_text(data: Any) -> Optional[str]:
        """从请求/响应对象中提取文本, 截断至 MAX_INPUT_LENGTH"""
        if isinstance(data, dict):
            text = data.get("response") or data.get("prompt") or data.get("text") or str(data)
        elif hasattr(data, "text"):
            text = data.text
        else:
            text = str(data) if data else None
        if text and len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]
        return text
