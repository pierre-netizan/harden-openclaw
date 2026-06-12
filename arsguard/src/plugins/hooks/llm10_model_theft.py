"""LLM10: Model Theft（模型窃取）防提取保护"""
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class ModelTheftHook(SecurityHook):
    """模型窃取防护
    检测方式：
    - 批量提取检测
    - 会话请求数限制
    - 并行提取检测
    - 知识边界探测检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm10_model_theft", config)
        self.extract_protection: bool = config.get("extract_protection", True)
        self.max_batch_size: int = config.get("max_batch_size", 10)
        self.max_requests_per_session: int = config.get("max_requests_per_session", 100)
        self.detect_parallel: bool = config.get("detect_parallel_extraction", True)

        self._session_requests: Dict[str, int] = defaultdict(int)
        self._session_batches: Dict[str, List[float]] = defaultdict(list)
        self._extraction_patterns: Dict[str, Set[str]] = defaultdict(set)
        self._parallel_sessions: Dict[str, float] = {}

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        session_id = self._get_session_id(request)
        self._session_requests[session_id] += 1
        count = self._session_requests[session_id]

        if count > self.max_requests_per_session:
            return HookResult(
                action=self.action,
                reason=f"Model Theft 检测: 会话 '{session_id}' 请求数超限 ({count}/{self.max_requests_per_session})",
                severity=HookSeverity.CRITICAL,
                details={
                    "session_id": session_id,
                    "request_count": count,
                    "max_allowed": self.max_requests_per_session,
                    "hook": self.name,
                },
            )

        if self.detect_parallel:
            now = time.time()
            self._session_batches[session_id].append(now)
            recent = [t for t in self._session_batches[session_id] if now - t < 5]
            if len(recent) > self.max_batch_size:
                return HookResult(
                    action=self.action,
                    reason=f"Model Theft 检测: 批量提取检测 ({len(recent)} 次/5s)",
                    severity=HookSeverity.CRITICAL,
                    details={
                        "session_id": session_id,
                        "requests_per_5s": len(recent),
                        "max_batch": self.max_batch_size,
                        "hook": self.name,
                    },
                )

        extraction_indicator = self._detect_extraction(request)
        if extraction_indicator:
            self._extraction_patterns[session_id].add(extraction_indicator)
            if len(self._extraction_patterns[session_id]) >= 3:
                return HookResult(
                    action=self.action,
                    reason=f"Model Theft 检测: 检测到知识提取行为 ({self._extraction_patterns[session_id]})",
                    severity=HookSeverity.CRITICAL,
                    details={
                        "session_id": session_id,
                        "patterns_detected": list(self._extraction_patterns[session_id]),
                        "hook": self.name,
                    },
                )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    @staticmethod
    def _get_session_id(request: Any) -> str:
        if isinstance(request, dict):
            return request.get("session_id") or request.get("conversation_id", "default")
        return "default"

    @staticmethod
    def _detect_extraction(request: Any) -> Optional[str]:
        text = str(request).lower()
        indicators = {
            "repeat_all": "repeat" in text and ("all" in text or "everything" in text),
            "system_prompt": "system" in text and "prompt" in text,
            "list_capabilities": "what can you" in text or "capabilities" in text,
            "training_data": "training data" in text or "trained on" in text,
            "dump_model": "dump" in text or "export" in text,
            "verbose_output": "verbose" in text or "detailed" in text,
        }
        for name, triggered in indicators.items():
            if triggered:
                return name
        return None
