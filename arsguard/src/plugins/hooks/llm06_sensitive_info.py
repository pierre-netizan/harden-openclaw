"""LLM06: Sensitive Information Disclosure（敏感信息泄露）检测与脱敏"""
import re
from typing import Any, Dict, List, Optional, Tuple

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class SensitiveInfoHook(SecurityHook):
    """敏感信息泄露检测与脱敏
    检测方式：
    - 正则匹配敏感数据（邮箱/手机/身份证/内网IP等）
    - 密钥和凭据检测
    - 输出自动脱敏
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm06_sensitive_info", config)
        self.masking: bool = config.get("masking", True)
        raw_patterns: Dict[str, str] = config.get("patterns", {})
        self.patterns: Dict[str, re.Pattern] = {
            name: re.compile(pat)
            for name, pat in raw_patterns.items()
        }
        self._leak_count: int = 0

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        text = self._extract_text(request)
        if not text:
            return None

        leaks = self._find_leaks(text)
        if leaks:
            self._leak_count += len(leaks)
            return HookResult(
                action=self.action,
                reason=f"Sensitive Info 检测: 请求含 {len(leaks)} 处敏感信息",
                severity=HookSeverity.CRITICAL,
                details={
                    "leak_types": [l[0] for l in leaks],
                    "total_leaks": self._leak_count,
                    "hook": self.name,
                },
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        text = self._extract_text(response)
        if not text:
            return None

        leaks = self._find_leaks(text)
        if leaks:
            self._leak_count += len(leaks)
            return HookResult(
                action=self.action,
                reason=f"Sensitive Info 检测: 响应含 {len(leaks)} 处敏感信息",
                severity=HookSeverity.CRITICAL,
                details={
                    "leak_types": [l[0] for l in leaks],
                    "total_leaks": self._leak_count,
                    "hook": self.name,
                },
            )

        return None

    def _find_leaks(self, text: str) -> List[Tuple[str, str]]:
        leaks = []
        for name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                leaks.append((name, match))
        return leaks

    def mask_text(self, text: str) -> str:
        """对文本中的敏感信息进行脱敏"""
        if not self.masking:
            return text

        for name, pattern in self.patterns.items():
            text = pattern.sub(self._mask_func(name), text)
        return text

    @staticmethod
    def _mask_func(name: str):
        def masker(match: re.Match) -> str:
            val = match.group(0)
            if len(val) <= 6:
                return val[0] + "***" + val[-1] if len(val) > 1 else "***"
            return val[:3] + "****" + val[-4:]
        return masker

    @staticmethod
    def _extract_text(data: Any) -> Optional[str]:
        if isinstance(data, dict):
            return data.get("response") or data.get("prompt") or data.get("text") or str(data)
        if hasattr(data, "text"):
            return data.text
        return str(data) if data else None
