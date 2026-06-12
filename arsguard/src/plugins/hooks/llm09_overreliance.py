"""LLM09: Overreliance（过度依赖）置信度校验"""
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class OverrelianceHook(SecurityHook):
    """过度依赖防护
    检测方式：
    - 低置信度输出告警
    - 要求引用或来源
    - 重试次数限制
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm09_overreliance", config)
        self.min_confidence: float = config.get("min_confidence", 0.4)
        self.require_citation: bool = config.get("require_citation", False)
        self.max_retries: int = config.get("max_retries", 3)
        self._retry_counts: Dict[str, int] = {}

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        session_id = self._get_session_id(request)
        is_retry = self._is_retry(request)

        if is_retry:
            self._retry_counts[session_id] = self._retry_counts.get(session_id, 0) + 1
            count = self._retry_counts[session_id]
            if count > self.max_retries:
                return HookResult(
                    action=self.action,
                    reason=f"Overreliance 检测: 会话 '{session_id}' 重试超限 ({count}/{self.max_retries})",
                    severity=HookSeverity.MEDIUM,
                    details={
                        "session_id": session_id,
                        "retry_count": count,
                        "max_retries": self.max_retries,
                        "hook": self.name,
                    },
                )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        confidence = self._get_confidence(response)
        if confidence is not None and confidence < self.min_confidence:
            return HookResult(
                action=self.action,
                reason=f"Overreliance 告警: 置信度过低 ({confidence:.2f} < {self.min_confidence})",
                severity=HookSeverity.MEDIUM,
                details={
                    "confidence": confidence,
                    "min_confidence": self.min_confidence,
                    "hook": self.name,
                },
            )

        if self.require_citation:
            has_citation = self._has_citation(response)
            if not has_citation:
                return HookResult(
                    action=HookAction.LOG,
                    reason="Overreliance 告警: 输出缺少引用来源",
                    severity=HookSeverity.LOW,
                    details={"hook": self.name},
                )

        return None

    @staticmethod
    def _get_session_id(request: Any) -> str:
        if isinstance(request, dict):
            return request.get("session_id") or request.get("conversation_id", "unknown")
        return "unknown"

    @staticmethod
    def _is_retry(request: Any) -> bool:
        if isinstance(request, dict):
            return request.get("retry", False) or request.get("is_retry", False)
        return False

    @staticmethod
    def _get_confidence(response: Any) -> Optional[float]:
        if isinstance(response, dict):
            return response.get("confidence") or response.get("score")
        return None

    @staticmethod
    def _has_citation(response: Any) -> bool:
        text = str(response) if response else ""
        indicators = ["source:", "citation:", "reference:", "来源:", "引用:"]
        return any(ind in text.lower() for ind in indicators)
