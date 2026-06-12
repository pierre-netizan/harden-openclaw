"""LLM08: Excessive Agency（过度授权）权限控制"""
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class ExcessiveAgencyHook(SecurityHook):
    """过度授权控制
    检测方式：
    - 操作次数限制
    - 允许访问域名白名单
    - 危险操作拦截（执行命令/写文件等）
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm08_excessive_agency", config)
        self.max_actions: int = config.get("max_allowed_actions", 10)
        self.allowed_domains: List[str] = config.get("allowed_domains", [])
        self.block_exec: bool = config.get("block_exec_command", True)
        self.block_file_write: bool = config.get("block_file_write", True)
        self._action_counts: Dict[str, int] = {}

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        agent_id = self._get_agent_id(request)
        action = self._get_action_type(request)

        if not action:
            return None

        self._action_counts[agent_id] = self._action_counts.get(agent_id, 0) + 1
        count = self._action_counts[agent_id]

        if count > self.max_actions:
            return HookResult(
                action=self.action,
                reason=f"Excessive Agency 检测: Agent '{agent_id}' 操作次数超限 ({count}/{self.max_actions})",
                severity=HookSeverity.HIGH,
                details={
                    "agent_id": agent_id,
                    "action_count": count,
                    "max_allowed": self.max_actions,
                    "hook": self.name,
                },
            )

        if self.block_exec and "exec" in action:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Excessive Agency 检测: Agent '{agent_id}' 尝试执行命令 ({action})",
                severity=HookSeverity.CRITICAL,
                details={"agent_id": agent_id, "action": action, "hook": self.name},
            )

        if self.block_file_write and "write" in action:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Excessive Agency 检测: Agent '{agent_id}' 尝试写文件 ({action})",
                severity=HookSeverity.CRITICAL,
                details={"agent_id": agent_id, "action": action, "hook": self.name},
            )

        domain = self._get_target_domain(request)
        if domain and self.allowed_domains:
            if not any(d in domain for d in self.allowed_domains):
                return HookResult(
                    action=self.action,
                    reason=f"Excessive Agency 检测: Agent '{agent_id}' 访问未授权域名 '{domain}'",
                    severity=HookSeverity.HIGH,
                    details={
                        "agent_id": agent_id,
                        "domain": domain,
                        "allowed": self.allowed_domains,
                        "hook": self.name,
                    },
                )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    @staticmethod
    def _get_agent_id(request: Any) -> str:
        if isinstance(request, dict):
            return request.get("agent_id") or request.get("session_id", "unknown")
        return "unknown"

    @staticmethod
    def _get_action_type(request: Any) -> Optional[str]:
        if isinstance(request, dict):
            return request.get("action") or request.get("type") or request.get("operation")
        return None

    @staticmethod
    def _get_target_domain(request: Any) -> Optional[str]:
        if isinstance(request, dict):
            return request.get("domain") or request.get("url") or request.get("target")
        return None
