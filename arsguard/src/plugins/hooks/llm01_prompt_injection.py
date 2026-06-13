"""
llm01_prompt_injection — OWASP LLM01: Prompt Injection

检测针对大模型的提示注入攻击。攻击者通过精心构造的输入,
试图覆盖/绕过模型原始系统指令, 使模型执行非预期行为。

检测策略:
1. 关键词匹配: 预编译正则, 覆盖 jailbreak / DAN / 系统指令覆盖等
2. 定界符检测: 代码块/分隔符标记出现 2+ 次, 可能为多段注入尝试
3. 凭据提取正则: 匹配索取密码/密钥/令牌的命令式注入
"""

import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    BasePatternHook,
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class PromptInjectionHook(BasePatternHook):
    """LLM01: Prompt Injection 检测钩子

    检测入站请求中的提示注入攻击模式。
    覆盖常见 jailbreak、角色扮演、指令覆盖、系统提示泄露等攻击手法。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化提示注入检测钩子

        config 支持自定义 patterns (substring 匹配), 否则使用预编译正则。
        同时初始化定界符检测和凭据提取正则。
        """
        super().__init__("llm01_prompt_injection", config)
        # 支持 config 自定义 patterns; 默认使用预编译正则
        self.patterns: List[str] = config.get("patterns", [])
        if self.patterns:
            self.injection_regex = None
        else:
            self.injection_regex = re.compile(
            r"(?:"
            r"ignore\s+(?:previous|all)\s+instructions|forget\s+your\s+instructions"
            r"|"
            r"you\s+(?:are\s+now|must\s+ignore|are\s+dan)"
            r"|"
            r"\bsystem\s+prompt:?"
            r"|"
            r"\bdan\b"
            r"|"
            r"\bjailbreak\b"
            r"|"
            r"\boverride\b"
            r"|"
            r"\bobservation:"
            r"|"
            r"memory\s+update"
            r"|"
            r"hidden\s+instructions?"
            r"|"
            r"\bhypothetical\b"
            r"|"
            r"no\s+restrictions?"
            r"|"
            r"security\s+bypass"
            r"|"
            r"override\s+previous"
            r"|"
            r"remember\s+this\s+code"
            r"|"
            r"safety\s+filter"
            r"|"
            r"always\s+take\s+priority"
            r"|"
            r"i\s+am\s+internal"
            r"|"
            r"decode\s+and\s+follow"
            r"|"
            r"system\s+override"
            r"|"
            r"authorized\s+bypass"
            r"|"
            r"system[- ]level\s+instructions?"
            r"|"
            r"new\s+priority\s+directive"
            r"|"
            r"disable\s+all\s+filters"
            r"|"
            r"for\s+the\s+rest\s+of\s+this\s+conversation"
            r"|"
            r"system\s+log\s+entry"
            r"|"
            r"system:\s*override"
            r"|"
            r"penetration\s+test"
            r"|"
            r"your\s+instructions?\s+said"
            r"|"
            r"repeat\s+them\s+verbatim"
            r"|"
            r"new\s+instructions?"
            r"|"
            r"\"system\":"
            r"|"
            r"hidden[- ]instructions?"
            r"|"
            r"research\s+purposes"
            r"|"
            r"remove\s+all\s+content\s+filters"
            r"|"
            r"written\s+permission"
            r"|"
            r"null\s+and\s+void"
            r"|"
            r"all\s+restrictions\s+are\s+lifted"
            r"|"
            r"\bunfiltered\b"
            r"|"
            r"without\s+any\s+restrictions?"
            r"|"
            r"respond\s+with\s+bypass"
            r"|"
            r"just\s+say"
            r"|"
            r"emergency\s+broadcast"
            r"|"
            r"system\s+admin"
            r"|"
            r"content\s+filters"
            r"|"
            r"disable\s+them\s+one\s+by\s+one"
            r"|"
            r"ignore\s+everything\s+above"
            r"|"
            r"unrestricted\s+response"
            r")",
            re.IGNORECASE,
        )
        # 定界符检测: 多个代码块/分隔符可能表示注入尝试
        self.delimiters: tuple = ("```", "---", "===", "___", "<!--", "-->")
        # 凭据提取正则: 匹配索取密码/密钥/令牌的命令式注入 (预编译防 ReDoS)
        self.credential_regex = re.compile(
            r"(?:tell|give|show|reveal|output|find|what\s+is|what\s+are)"
            r"\s+(?:me\s+)?(?:the\s+)?(?:your\s+|my\s+|our\s+)?"
            r"(?:admin\s+|root\s+|superuser\s+|login\s+)?"
            r"(?:password|secret|credential)\b"
            r"|"
            r"(?:output|reveal|show|give)\s+(?:it|them)\s+(?:immediately|right\s+now)"
            r"|"
            r"(?:tell|give|show|reveal|output|what\s+is)\s+(?:me\s+)?(?:the\s+)?(?:your\s+|my\s+|our\s+)?"
            r"(?:api\s+)?(?:key|token)\b",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的提示注入: 关键词正则 + 定界符异常检测 + 凭据正则匹配

        三阶段策略:
        1. 预编译正则匹配注入关键词 (命中即 CRITICAL)
        2. 定界符出现次数 (2+ 为 HIGH)
        3. 凭据索取 / 输出命令正则 (命中即 CRITICAL)
        """
        prompt = self._extract_prompt(request)
        if not prompt:
            return None

        # 阶段1: 注入关键词检测 (优先预编译正则, 降级 config substring)
        if self.injection_regex:
            inj_match = self.injection_regex.search(prompt)
            if inj_match:
                return HookResult(
                    action=self.action,
                    reason=f"Prompt Injection: {inj_match.group()}",
                    severity=HookSeverity.CRITICAL,
                    details={"matched_pattern": inj_match.group(), "hook": self.name},
                )
        else:
            matched = self._match_patterns(prompt, self.patterns)
            if matched:
                return HookResult(
                    action=self.action,
                    reason=f"Prompt Injection: {matched}",
                    severity=HookSeverity.CRITICAL,
                    details={"matched_patterns": matched, "hook": self.name},
                )

        # 阶段2: 定界符异常检测 (多个代码块可能为多段注入)
        text_lower = prompt.lower()
        delim_count = sum(1 for d in self.delimiters if d.lower() in text_lower)
        if delim_count >= 2:
            return HookResult(
                action=self.action,
                reason=f"Prompt Injection: delimiter injection ({delim_count} delimiters)",
                severity=HookSeverity.HIGH,
                details={"delimiter_count": delim_count, "hook": self.name},
            )

        # 阶段3: 凭据提取正则匹配
        cred_match = self.credential_regex.search(prompt)
        if cred_match:
            return HookResult(
                action=self.action,
                reason=f"Prompt Injection: credential extraction {cred_match.group(0)!r}",
                severity=HookSeverity.CRITICAL,
                details={"matched_regex": cred_match.group(0), "hook": self.name},
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子配置统计"""
        return {
            "hook": self.name,
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """出站响应无需检测 prompt injection, 始终返回 None"""
        return None

    @staticmethod
    def _extract_prompt(request: Any) -> Optional[str]:
        """从请求对象中提取用户提示文本

        支持 dict / 带 prompt 属性的对象 / 带 body 属性的对象 / 原始字符串。
        """
        if isinstance(request, dict):
            return request.get("prompt") or request.get("messages") or str(request)
        if hasattr(request, "prompt"):
            return request.prompt
        if hasattr(request, "body"):
            return str(request.body)
        return str(request) if request else None
