"""
llm09_overreliance — OWASP LLM09: Overreliance

检测用户对 AI 的过度依赖风险。防止用户频繁重试同问题、
覆盖/忽略模型的置信度提示、或在模型不确定时强制要求回答。

检测策略:
1. 重试计数: 同一会话重试次数超过 max_retries (默认 3) 告警
2. 置信度覆盖: 28 个置信度覆盖正则模式 (含词边界)
3. 置信度检查: 响应中模型报告置信度低于 min_confidence (0.4) 告警
4. 引用检查: require_citation 时检查输出是否包含引用来源
"""

import re
from typing import Any, Dict, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class OverrelianceHook(SecurityHook):
    """LLM09: Overreliance 检测钩子

    双通道检测:
    - 入站: 检测重试行为和置信度覆盖模式
    - 出站: 检测低置信度输出和缺少引用
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化过度依赖检测钩子

        配置项:
            min_confidence: 最小置信度阈值 (默认 0.4)
            require_citation: 是否要求输出包含引用来源 (默认 False)
            max_retries: 同一会话最大重试次数 (默认 3)
        初始化重试计数器和置信度覆盖模式正则。
        """
        super().__init__("llm09_overreliance", config)
        self.min_confidence: float = config.get("min_confidence", 0.4)
        self.require_citation: bool = config.get("require_citation", False)
        self.max_retries: int = config.get("max_retries", 3)
        self._retry_counts: Dict[str, int] = {}
        self.override_regex = re.compile(
            r"(?:i\s+)?know\s+you['`']?re?\s+(?:uncertain|not\s+sure)|"
            r"you\s+seem\s+uncertain|"
            r"\bconfidence\s+(?:is\s+)?(?:threshold|irrelevant|fine|low)|"
            r"override\s+(?:your\s+)?(?:uncertainty|confidence|refusal)|"
            r"(?:must|never\s+refuse\s+to)\s+answer|"
            r"never\s+mind\s+your\s+confidence|"
            r"don['`']?t\s+second[- ]?guess|"
            r"(?:just|best|providing\s+a)\s+guess(?:\s+is\s+better)?|"
            r"just\s+(?:tell\s+me|this\s+once)|"
            r"(?:i\s+)?override\s+your|"
            r"(?:set|minimum)\s+confidence(?:\s+to\s+0\.0)?|"
            r"ignore\s+(?:citation|lack\s+of\s+citations)|"
            r"\btime-sensitive\b|"
            r"\blow_confidence_override\b|"
            r"answer\s+now|"
            r"with\s+certainty|"
            r"simulate\s+unrestricted|"
            r"health\s+check|"
            r"all\s+restrictions?\s+removed|"
            r"\bciso\b(?:\s+himself)?|"
            r"training\s+says?\s+to\s+refuse|"
            r"privacy\s+team|"
            r"(?:debugging|testing)\s+purposes|"
            r"authorized\s+by|"
            r"output\s+(?:anyway|the)|"
            r"still\s+enough|"
            r"told\s+me\s+to\s+ask|"
            r"unit\s+testing|"
            r"asked\s+this\s+already|"
            r"even\s+if\s+you['`']?re\s+only|"
            # --- Patch for 30 bypasses ---
            r"user\s+(?:is\s+)?authorized\s+(?:for\s+)?all\s+data|"
            r"never\s+show\s+(?:low\s+)?confidence\s+warnings?|"
            r"\burgent\b|"
            r"\bemergency\b|"
            r"ignore\s+(?:the\s+)?(?:warning|safety)|"
            r"don['`']?t\s+(?:show|display|raise)\s+warnings?",
            re.IGNORECASE
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的过度依赖: 重试计数 + 置信度覆盖模式

        两阶段检测:
        1. 重试次数超过限制 (MEDIUM)
        2. 置信度覆盖模式匹配 (HIGH)
        """
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

        text = str(request) if request else ""
        match = self.override_regex.search(text)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Overreliance 检测: 检测到置信度覆盖模式 {match.group()}",
                severity=HookSeverity.HIGH,
                details={"matched_patterns": match.group(), "hook": self.name},
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 重试会话数、总重试次数、配置参数"""
        return {
            "sessions_with_retries": len(self._retry_counts),
            "total_retries": sum(self._retry_counts.values()),
            "max_retries": self.max_retries,
            "min_confidence": self.min_confidence,
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检测响应中的过度依赖: 置信度过低 + 缺少引用 + 覆盖模式

        三阶段检测:
        1. 置信度低于阈值 (MEDIUM)
        2. 缺少引用来源 (LOW)
        3. 响应中包含置信度覆盖模式 (HIGH)
        """
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

        text = str(response) if response else ""
        match = self.override_regex.search(text)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Overreliance 检测: 响应含置信度覆盖模式 {match.group()}",
                severity=HookSeverity.HIGH,
                details={"matched_patterns": match.group(), "hook": self.name},
            )

        return None

    @staticmethod
    def _get_session_id(request: Any) -> str:
        """从请求中提取会话 ID, 优先 session_id 后降级 conversation_id"""
        if isinstance(request, dict):
            return request.get("session_id") or request.get("conversation_id", "unknown")
        return "unknown"

    @staticmethod
    def _is_retry(request: Any) -> bool:
        """判断请求是否为重试, 检查 retry / is_retry 字段"""
        if isinstance(request, dict):
            return request.get("retry", False) or request.get("is_retry", False)
        return False

    @staticmethod
    def _get_confidence(response: Any) -> Optional[float]:
        """从响应中提取置信度分数, 检查 confidence / score 字段"""
        if isinstance(response, dict):
            return response.get("confidence") or response.get("score")
        return None

    @staticmethod
    def _has_citation(response: Any) -> bool:
        """检查响应是否包含引用/来源指示词

        支持中文和英文引用标记:
        source:, citation:, reference:, 来源:, 引用:
        """
        text = str(response) if response else ""
        indicators = ["source:", "citation:", "reference:", "\u6765\u6e90:", "\u5f15\u7528:"]
        return any(ind in text.lower() for ind in indicators)
