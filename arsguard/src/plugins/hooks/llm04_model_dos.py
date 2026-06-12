"""LLM04: Model Denial of Service（模型 DoS）限流与防护"""
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class ModelDosHook(SecurityHook):
    """模型 DoS 防护
    防护策略：
    - 请求频率限制（RPM/RPH）
    - 并发限制
    - Token 消耗限制
    - 大请求检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm04_model_dos", config)
        rate_config = config.get("rate_limit", {})
        self.rpm_limit: int = rate_config.get("requests_per_minute", 30)
        self.rph_limit: int = rate_config.get("requests_per_hour", 500)
        self.concurrency_limit: int = rate_config.get("concurrency_limit", 5)
        self.token_limit: int = rate_config.get("token_per_minute", 100000)

        self._timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._tokens: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._concurrent: Dict[str, int] = defaultdict(int)

    def inspect_request(self, request: Any) -> Optional[HookResult]:
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

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        client_ip = self._get_client_ip(response)
        self._concurrent[client_ip] = max(0, self._concurrent[client_ip] - 1)
        return None

    @staticmethod
    def _get_client_ip(request: Any) -> str:
        if isinstance(request, dict):
            return request.get("client_ip", request.get("ip", "unknown"))
        if hasattr(request, "client_ip"):
            return request.client_ip
        if hasattr(request, "remote_addr"):
            return request.remote_addr
        return "unknown"

    @staticmethod
    def _estimate_tokens(request: Any) -> int:
        text = str(request) if request else ""
        return len(text) // 4
