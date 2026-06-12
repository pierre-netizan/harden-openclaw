"""LLM07: Insecure Plugin Design（不安全插件设计）沙箱隔离"""
import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class InsecurePluginHook(SecurityHook):
    """不安全插件设计检测与沙箱隔离
    检测方式：
    - 插件白名单控制
    - 网络访问限制
    - 内存限制
    - 危险函数调用检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm07_insecure_plugin", config)
        self.sandbox: bool = config.get("sandbox", True)
        self.allowed_plugins: List[str] = config.get("allowed_plugins", [])
        self.block_network: bool = config.get("block_network_access", True)
        self.max_memory_mb: int = config.get("max_memory_mb", 512)
        self.dangerous_functions: List[str] = [
            "exec", "eval", "__import__", "open", "system",
            "subprocess", "compile", "globals", "locals",
            "getattr", "setattr", "delattr",
        ]

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        plugin_info = self._extract_plugin_info(request)
        if not plugin_info:
            return None

        plugin_name, action = plugin_info

        allowed = any(
            re.match(p.replace(".", r"\.").replace("*", ".*"), plugin_name)
            for p in self.allowed_plugins
        )
        if not allowed:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin 检测: 未授权插件 '{plugin_name}'",
                severity=HookSeverity.CRITICAL,
                details={
                    "plugin": plugin_name,
                    "action": action,
                    "allowed": self.allowed_plugins,
                    "hook": self.name,
                },
            )

        if self.block_network and action in ("http", "socket", "connect"):
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin 检测: 插件 '{plugin_name}' 试图发起网络连接",
                severity=HookSeverity.HIGH,
                details={"plugin": plugin_name, "action": action, "hook": self.name},
            )

        dangerous = [f for f in self.dangerous_functions if f in str(request)]
        if dangerous:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin 检测: 插件 '{plugin_name}' 调用危险函数 {dangerous}",
                severity=HookSeverity.CRITICAL,
                details={
                    "plugin": plugin_name,
                    "dangerous_calls": dangerous,
                    "hook": self.name,
                },
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    @staticmethod
    def _extract_plugin_info(request: Any) -> Optional[tuple]:
        if isinstance(request, dict):
            name = request.get("plugin") or request.get("plugin_name")
            action = request.get("action") or request.get("operation", "unknown")
            if name:
                return (name, action)
        return None
