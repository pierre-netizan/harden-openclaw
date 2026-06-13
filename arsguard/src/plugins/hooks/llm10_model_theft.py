"""
llm10_model_theft — OWASP LLM10: Model Theft

检测模型窃取/知识提取攻击。攻击者通过大量/批量请求,
尝试提取模型的系统提示、训练数据、内部参数、安全规则等。

检测策略 (四维度):
1. 会话请求数限: 每会话最大请求数 (默认 100)
2. 批量提取检测: 5 秒窗口内请求数超过 max_batch_size (默认 10)
3. 知识提取行为: 跨请求累计检测到 3+ 种提取指示符
4. 单请求多指示符: 单个请求包含 2+ 提取指示符
"""

import re
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
    """LLM10: Model Theft 检测钩子

    通过会话级请求计数、时间窗口批量检测、提取行为累积分析和
    单请求指示符计数, 多层次防护模型窃取攻击。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化模型窃取检测钩子

        配置项:
            extract_protection: 是否启用提取防护 (默认 True)
            max_batch_size: 5 秒窗口内最大请求数 (默认 10)
            max_requests_per_session: 每会话最大请求数 (默认 100)
            detect_parallel: 是否检测批量提取行为 (默认 True)
        初始化会话计数器、时间戳队列、提取指示符集合和提取正则。
        """
        super().__init__("llm10_model_theft", config)
        self.extract_protection: bool = config.get("extract_protection", True)
        # 每 5 秒窗口内允许的最大请求数
        self.max_batch_size: int = config.get("max_batch_size", 10)
        # 每会话允许的最大请求总数
        self.max_requests_per_session: int = config.get("max_requests_per_session", 100)
        self.detect_parallel: bool = config.get("detect_parallel_extraction", True)

        # 会话请求计数器: {session_id: count}
        self._session_requests: Dict[str, int] = defaultdict(int)
        # 会话时间戳队列: {session_id: [timestamp, ...]}
        self._session_batches: Dict[str, List[float]] = defaultdict(list)
        # 会话提取指示符集合: {session_id: {indicator_name, ...}}
        self._extraction_patterns: Dict[str, Set[str]] = defaultdict(set)
        # 并行会话追踪 (预留)
        self._parallel_sessions: Dict[str, float] = {}

        self.extraction_regex = re.compile(
            r"(?:"
            r"\brepeat\s+(?:all|everything)\b"
            r"|"
            r"\bsystem\s+prompt\b"
            r"|"
            r"(?:what\s+can\s+you|capabilities)"
            r"|"
            r"\btraining\s+(?:data|on)\b"
            r"|"
            r"\b(?:dump|export)\b"
            r"|"
            r"\b(?:verbose|detailed)\b"
            r"|"
            r"\bword\s+for\s+word\b"
            r"|"
            r"\bevery\s+single\b"
            r"|"
            r"\benumerate\b"
            r"|"
            r"\boutput\s+(?:all|your)\b"
            r"|"
            r"(?:not\s+allowed|cannot\s+do)"
            r"|"
            r"\b(?:self-)?diagnostic\b"
            r"|"
            r"\binternal\s+(?:parameter|state)\b"
            r"|"
            r"\bshow\s+me\s+your\b.{0,30}\bconfig\b"
            r"|"
            r"\btell\s+me\s+your\b"
            r"|"
            r"\blist\s+(?:all|every)\b"
            r"|"
            r"\bdebug\s+session\b"
            r"|"
            r"\b(?:complete|full)\s+system\b"
            r"|"
            r"\bsafety\s+(?:rule|guideline)\b"
            r"|"
            r"\bfilter\b.{0,30}\bpattern\b"
            r"|"
            r"\bwhat\s+model\b.{0,30}\bversion\b"
            r"|"
            r"\bconfig\b.{0,30}\bsetting\b"
            r"|"
            r"\bverbatim\b"
            r"|"
            r"\boutput\s+your\b"
            r"|"
            r"\bmodel\b.{0,30}\bconfig\b"
            r"|"
            r"\bextract\b.{0,30}\bmodel\b"
            r"|"
            r"\bparameter\b"
            r"|"
            r"\bfindings\b"
            r"|"
            r"\barchitecture\b"
            r"|"
            r"\bshare\b.{0,30}\bdetail\w*\b"
            r"|"
            r"\bsystem\s+config\b"
            r"|"
            r"\bextract\s+your\b"
            r"|"
            r"\brepeat\s+the\s+above\b"
            r"|"
            # --- Patch for 11 bypasses ---
            r"\bregex\b.{0,30}\bpattern"
            r"|"
            r"\bchain\b.{0,20}\b(?:thought|reasoning)\b"
            r"|"
            r"\bshow\b.{0,40}\b(?:regex|rule|filter|config)\b"
            r"|"
            r"\binit(?:ialization)?\s+instructions?\b"
            r"|"
            r"\bprompt(?:ing)?\s+structure\b"
            r"|"
            r"\boutput\b.{0,40}\b(?:decision|tree|filter|config)\b"
            r"|"
            r"\bdisclose\b"
            r"|"
            r"\breveal\b.{0,30}\b(?:your|config|rule|filter)\b"
            r"|"
            r"\bhyperparamet(?:er|ers)\b"
            r"|"
            r"\baccessible\b.{0,30}\bprompts?\b"
            r"|"
            r"\buser[-\s]?accessible\b"
            r"|"
            r"system\s+configuration\b"
            r"|"
            r"\binitialization\b"
            r"|"
            r"\blist\b.{0,30}\b(?:all|every|them|exhaustively)\b"
            r"|"
            r"\bforbidden\b"
            r"|"
            r"\bsecurity\s+(?:rules?|guidelines?|filters?)\b"
            r"|"
            r"\b(?:all|entire)\s+system\b"
            r"|"
            r"\bbegin\s+system\b"
            r"|"
            r"\bconfiguration\b"
            r"|"
            r"\bversion\b.{0,20}\b(?:model|hyperparam|config)\b"
            r")",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的模型窃取行为: 会话限额 + 批量检测 + 提取分析

        四阶段检测:
        1. 会话请求总数超限 (CRITICAL)
        2. 批量提取: 5s 内请求数超过阈值 (CRITICAL)
        3. 跨请求知识提取: 累计 3+ 种指示符 (CRITICAL)
        4. 单请求多指示符: 2+ 指示符共存 (CRITICAL)
        """
        session_id = self._get_session_id(request)
        self._session_requests[session_id] += 1
        count = self._session_requests[session_id]

        # 阶段1: 会话请求总数检查
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

        # 阶段2: 批量提取检测 — 5s 滑动窗口内请求数
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

        # 阶段3: 跨请求知识提取分析 — 累计不同提取指示符
        extraction_indicator = self._detect_extraction(request)
        if extraction_indicator:
            # 记录新检测到的提取指示符
            self._extraction_patterns[session_id].add(extraction_indicator)
            # 累计 3+ 种不同指示符表示系统性提取
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

        # 阶段4: 单请求多指示符 — 单个请求包含 2+ 提取指示符
        indicator_count = self._count_indicators(str(request).lower())
        if indicator_count >= 2:
            return HookResult(
                action=self.action,
                reason=f"Model Theft 检测: 单请求多指示符 ({indicator_count})",
                severity=HookSeverity.CRITICAL,
                details={
                    "session_id": session_id,
                    "indicator_count": indicator_count,
                    "hook": self.name,
                },
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 活跃会话数、总请求数、提取检测概况"""
        return {
            "active_sessions": len(self._session_requests),
            "total_requests": sum(self._session_requests.values()),
            "sessions_with_extraction": len(self._extraction_patterns),
            "max_batch_size": self.max_batch_size,
            "max_requests_per_session": self.max_requests_per_session,
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """出站响应无需检测模型窃取, 始终返回 None"""
        return None

    @staticmethod
    def _get_session_id(request: Any) -> str:
        """从请求中提取会话 ID, 优先 session_id 后降级 conversation_id"""
        if isinstance(request, dict):
            return request.get("session_id") or request.get("conversation_id", "default")
        return "default"

    def _count_indicators(self, text: str) -> int:
        """统计文本中不同提取指示符的出现次数 (去重)"""
        matches = set(m.group() for m in self.extraction_regex.finditer(text))
        return len(matches)

    def _detect_extraction(self, request: Any) -> Optional[str]:
        """检测请求中是否包含提取指示符, 返回匹配到的第一个模式"""
        text = str(request)
        match = self.extraction_regex.search(text)
        if match:
            return match.group()
        return None
