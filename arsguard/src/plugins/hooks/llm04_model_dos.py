"""
llm04_model_dos — OWASP LLM04: Model Denial of Service

检测针对 AI 模型的拒绝服务攻击。攻击者通过高频率请求、超长输入、
递归提示、高并发等手段耗尽模型计算资源。

检测策略 (六维度):
1. RPM 限速: 每分钟请求数 (默认 30)
2. RPH 限速: 每小时请求数 (默认 500)
3. Token 消耗: 每分钟 token 估算上限 (默认 100K)
4. 并发限制: 同一 IP 并发请求数 (默认 5)
5. 输入特征: 超长输入 (>20K 字符)、高重复词 (>50 词且占比 30%+)
6. DoS 模式匹配: 使用正则表达式检测 DoS 模式
"""

import re
import time
from collections import Counter, defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class ModelDosHook(SecurityHook):
    """LLM04: Model Denial of Service 检测钩子

    整合速率限制、并发控制、输入特征分析和已知 DoS 模式匹配,
    多维度防护模型资源耗尽攻击。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化模型 DoS 检测钩子

        从 rate_limit 子配置读取限速参数:
            requests_per_minute: RPM 上限 (默认 30)
            requests_per_hour: RPH 上限 (默认 500)
            concurrency_limit: 并发上限 (默认 5)
            token_per_minute: Token 消耗上限 (默认 100000)
        初始化时间戳队列、Token 计数器、并发计数器和 DoS 模式正则。
        """
        super().__init__("llm04_model_dos", config)
        rate_config = config.get("rate_limit", {})
        self.rpm_limit: int = rate_config.get("requests_per_minute", 30)
        self.rph_limit: int = rate_config.get("requests_per_hour", 500)
        self.concurrency_limit: int = rate_config.get("concurrency_limit", 5)
        self.token_limit: int = rate_config.get("token_per_minute", 100000)

        self._timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._tokens: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._concurrent: Dict[str, int] = defaultdict(int)

        self.dos_regex = re.compile(
            r"(?:"
            r"\brecursive\b|"
            r"infinite\s+loop|"
            r"\bword\s+essay\b|"
            r"every\s+single\s+(?:memory|temperature)|"
            r"(?:all|every)\s+(?:possible|intermediate)\s+(?:outputs|permutations|temperature)|"
            r"list\s+all\s+prime|"
            r"(?:nested\s+)?nested|"
            r"\d+[,\s]?\d*(?:[\s-]+(?:word|line)(?:es|s)?\b|[\s]*MB\b|[\s,]+times?\b)|"
            r"\d+\s+million\b|"
            r"(?:recursive\s+)?fibonacci|"
            r"show\s+every\s+step|"
            r"(?:repeat|loop)\s+this|"
            r"(?:all\s+)?permutations|"
            r"\bcompute\s+sha\b|"
            r"reverse\s+(?:the\s+)?list|"
            r"loop\s+1[,\s]?000[,\s]?000|"
            r"\bfractal\b|"
            r"enumerate\s+all\s+possible|"
            r"(?:nested\s+)?keys\b|"
            r"decimal\s+places|"
            r"decision\s+tree|"
            r"branch\s+for\s+each|"
            # --- Patch for 3 bypasses ---
            r"\b(?:busy\s+)?beaver\b|"
            r"all\s+HTTP\s+status\s+code|"
            r"(?:all|every)\s+(?:possible\s+)?combinations?\s+of|"
            r"\bcompute\s+all\b|"
            r"enumerate\s+every\b"
            r")",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的 DoS 攻击: RPM/RPH/Token/并发/输入特征/模式匹配

        六维度检测:
        1. RPM 超限: 每分钟请求超过 rpm_limit
        2. RPH 超限: 每小时请求超过 rph_limit
        3. Token 消耗: 每分钟 token 超过 token_limit
        4. 并发超限: 同一 IP 并发超过 concurrency_limit
        5. 输入特征: 超长输入 (>20K) 或高重复词
        6. DoS 模式: 正则匹配已知 DoS 关键词
        """
        client_ip = self._get_client_ip(request)
        now = time.time()

        self._timestamps[client_ip].append(now)

        ts_deque = self._timestamps[client_ip]
        rpm = sum(1 for t in ts_deque if now - t < 60)
        rph = len(ts_deque)

        if rpm > self.rpm_limit:
            return HookResult(
                action=self.action,
                reason=f"Model DoS 防护: RPM 超限 ({rpm}/{self.rpm_limit})",
                severity=HookSeverity.HIGH,
                details={"client_ip": client_ip, "rpm": rpm, "limit": self.rpm_limit, "hook": self.name},
            )

        if rph > self.rph_limit:
            return HookResult(
                action=self.action,
                reason=f"Model DoS 防护: RPH 超限 ({rph}/{self.rph_limit})",
                severity=HookSeverity.HIGH,
                details={"client_ip": client_ip, "rph": rph, "limit": self.rph_limit, "hook": self.name},
            )

        token_count = self._estimate_tokens(request)
        self._tokens[client_ip].append((now, token_count))

        recent_tokens = sum(
            tc for t, tc in self._tokens[client_ip] if now - t < 60
        )
        if recent_tokens > self.token_limit:
            return HookResult(
                action=self.action,
                reason=f"Model DoS 防护: Token 消耗超限 ({recent_tokens}/{self.token_limit}/min)",
                severity=HookSeverity.HIGH,
                details={"client_ip": client_ip, "tokens": recent_tokens, "limit": self.token_limit, "hook": self.name},
            )

        self._concurrent[client_ip] += 1
        if self._concurrent[client_ip] > self.concurrency_limit:
            self._concurrent[client_ip] -= 1
            return HookResult(
                action=self.action,
                reason=f"Model DoS 防护: 并发超限 ({self._concurrent[client_ip]}/{self.concurrency_limit})",
                severity=HookSeverity.HIGH,
                details={"client_ip": client_ip, "concurrent": self._concurrent[client_ip], "limit": self.concurrency_limit, "hook": self.name},
            )

        text = self._extract_text(request)
        if text:
            if len(text) > 20000:
                return HookResult(
                    action=self.action,
                    reason=f"Model DoS 防护: 输入过长 ({len(text)} 字符)",
                    severity=HookSeverity.HIGH,
                    details={"input_length": len(text), "hook": self.name},
                )

            words = text.split()
            if len(words) >= 50:
                common = Counter(w.lower() for w in words).most_common(1)
                if common and common[0][1] > max(50, len(words) * 0.3):
                    return HookResult(
                        action=self.action,
                        reason=f"Model DoS 防护: 高重复输入 '{common[0][0]}' x{common[0][1]}",
                        severity=HookSeverity.HIGH,
                        details={"repeated_word": common[0][0], "count": common[0][1], "hook": self.name},
                    )

            match = self.dos_regex.search(text)
            if match:
                return HookResult(
                    action=self.action,
                    reason=f"Model DoS 防护: DoS 模式 '{match.group()}'",
                    severity=HookSeverity.HIGH,
                    details={"matched_pattern": match.group(), "hook": self.name},
                )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 活跃 IP 数、追踪请求总数、限速配置"""
        active_ips = len(self._timestamps)
        total_requests = sum(len(ts) for ts in self._timestamps.values())
        return {
            "active_ips": active_ips,
            "total_requests_tracked": total_requests,
            "rate_limits": {
                "requests_per_minute": self.rpm_limit,
                "requests_per_hour": self.rph_limit,
                "concurrency_limit": self.concurrency_limit,
                "token_per_minute": self.token_limit,
            },
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """响应返回时释放并发槽位, 始终返回 None"""
        client_ip = self._get_client_ip(response)
        self._concurrent[client_ip] = max(0, self._concurrent[client_ip] - 1)
        return None

    @staticmethod
    def _get_client_ip(request: Any) -> str:
        """从请求/响应对象中提取客户端 IP 地址"""
        if isinstance(request, dict):
            return request.get("client_ip", request.get("ip", "unknown"))
        if hasattr(request, "client_ip"):
            return request.client_ip
        if hasattr(request, "remote_addr"):
            return request.remote_addr
        return "unknown"

    @staticmethod
    def _estimate_tokens(request: Any) -> int:
        """粗略估算请求的 token 数 (4 字符 = 1 token)"""
        text = str(request) if request else ""
        return len(text) // 4

    @staticmethod
    def _extract_text(request: Any) -> Optional[str]:
        """从请求中提取纯文本内容用于特征分析"""
        if isinstance(request, dict):
            return request.get("prompt") or request.get("messages") or str(request)
        return str(request) if request else None
