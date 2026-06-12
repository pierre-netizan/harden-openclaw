"""LLM02: Insecure Output Handling（不安全输出处理）检测与过滤"""
import html
from typing import Any, Dict, List, Optional

from .hook_base import (
    BasePatternHook,
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class InsecureOutputHook(BasePatternHook):
    """检测并过滤不安全输出
    检测方式：
    - HTML/JS 注入（XSS）检测
    - 敏感信息泄露检测
    - 代码执行 payload 检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm02_insecure_output", config)
        self.filter_patterns: List[str] = config.get("filter_patterns", [])
        self.xss_patterns: List[str] = [
            "<script", "javascript:", "onerror=", "onload=",
            "onclick=", "onmouseover=", "eval(", "document.",
            "<iframe", "<embed", "<object",
        ]

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        output = self._extract_output(response)
        if not output:
            return None

        matched_xss = self._match_patterns(output, self.xss_patterns)
        if matched_xss:
            return HookResult(
                action=self.action,
                reason=f"Insecure Output 检测: 检测到 XSS/注入 payload {matched_xss}",
                severity=HookSeverity.CRITICAL,
                details={"matched_xss": matched_xss, "hook": self.name},
            )

        matched_sensitive = self._match_patterns(output, self.filter_patterns)
        if matched_sensitive:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Output 检测: 输出包含敏感信息 {matched_sensitive}",
                severity=HookSeverity.HIGH,
                details={"matched_sensitive": matched_sensitive, "hook": self.name},
            )

        return None

    @staticmethod
    def _extract_output(response: Any) -> Optional[str]:
        if isinstance(response, dict):
            return response.get("response") or response.get("text") or str(response)
        if hasattr(response, "text"):
            return response.text
        if hasattr(response, "body"):
            return str(response.body)
        return str(response) if response else None
