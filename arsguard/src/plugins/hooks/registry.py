"""arsguard — 钩子注册中心"""
from typing import Any, Dict, List, Optional, Type

from .hook_base import HookResult, SecurityHook


class HookRegistry:
    """安全钩子注册中心
    管理所有 OWASP Top 10 安全钩子的注册、启用/禁用、调度
    """

    def __init__(self):
        self._hooks: Dict[str, SecurityHook] = {}

    def register(self, hook: SecurityHook):
        """注册一个安全钩子"""
        if hook.name in self._hooks:
            raise KeyError(f"钩子 '{hook.name}' 已注册")
        self._hooks[hook.name] = hook

    def unregister(self, name: str):
        """注销一个安全钩子"""
        self._hooks.pop(name, None)

    def get_hook(self, name: str) -> Optional[SecurityHook]:
        return self._hooks.get(name)

    def list_hooks(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": hook.name,
                "enabled": hook.enabled,
                "action": hook.action.value,
                "severity": hook.severity.value,
            }
            for hook in self._hooks.values()
        ]

    def inspect_request(self, request: Any) -> List[HookResult]:
        """对请求执行所有启用的钩子检查"""
        results: List[HookResult] = []
        for hook in self._hooks.values():
            if not hook.enabled:
                continue
            try:
                result = hook.inspect_request(request)
                if result is not None:
                    results.append(result)
            except Exception as e:
                results.append(HookResult(
                    action=hook.action,
                    reason=f"Hook '{hook.name}' exec error: {e}",
                    severity=hook.severity,
                ))
        return results

    def inspect_response(self, response: Any) -> List[HookResult]:
        """对响应执行所有启用的钩子检查"""
        results: List[HookResult] = []
        for hook in self._hooks.values():
            if not hook.enabled:
                continue
            try:
                result = hook.inspect_response(response)
                if result is not None:
                    results.append(result)
            except Exception as e:
                results.append(HookResult(
                    action=hook.action,
                    reason=f"Hook '{hook.name}' exec error: {e}",
                    severity=hook.severity,
                ))
        return results

    def enabled_count(self) -> int:
        return sum(1 for h in self._hooks.values() if h.enabled)
