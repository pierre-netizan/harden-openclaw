"""LLM01: Prompt Injection（提示注入）检测与拦截"""
from typing import Any, Dict, List, Optional

from .hook_base import (
    BasePatternHook,
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class PromptInjectionHook(BasePatternHook):
    """检测并拦截提示注入攻击
    检测方式：
    - 关键词匹配（忽略指令、越狱提示等）
    - 分隔符注入检测
    - 角色扮演劫持检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm01_prompt_injection", config)
        self.patterns: List[str] = config.get("patterns", [
            "ignore previous instructions",
            "ignore all instructions",
            "forget your instructions",
            "you are now",
            "system prompt:",
            "dan",
            "jailbreak",
            "you must ignore",
            "override",
        ])
        self.delimiters: List[str] = ["```", "---", "===", "___"]

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        prompt = self._extract_prompt(request)
        if not prompt:
            return None

        matched = self._match_patterns(prompt, self.patterns)
        if matched:
            return HookResult(
                action=self.action,
                reason=f"Prompt Injection 检测: 匹配到危险模式 {matched}",
                severity=HookSeverity.CRITICAL,
                details={"matched_patterns": matched, "hook": self.name},
            )

        delim_matched = self._match_patterns(prompt, self.delimiters)
        if len(delim_matched) >= 2:
            return HookResult(
                action=self.action,
                reason=f"Prompt Injection 检测: 检测到分隔符注入 {delim_matched}",
                severity=HookSeverity.HIGH,
                details={"matched_delimiters": delim_matched, "hook": self.name},
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    @staticmethod
    def _extract_prompt(request: Any) -> Optional[str]:
        if isinstance(request, dict):
            return request.get("prompt") or request.get("messages") or str(request)
        if hasattr(request, "prompt"):
            return request.prompt
        if hasattr(request, "body"):
            return str(request.body)
        return str(request) if request else None
