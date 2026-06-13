"""
registry — arsguard 钩子注册中心

管理所有 OWASP Top 10 for AI Agents 安全钩子的生命周期:
注册/注销、启用/禁用、请求/响应调度。

调度策略:
- 遍历所有已注册且 enabled 的钩子, 依次执行 inspect_request / inspect_response
- 每个钩子独立捕获异常, 防止单钩子崩溃影响其他钩子
- 返回聚合结果列表, 供调用方决策 (任一 BLOCK 则拦截)
"""

from typing import Any, Dict, List, Optional, Type

from .hook_base import HookResult, SecurityHook


class HookRegistry:
    """安全钩子注册中心

    管理所有 OWASP Top 10 安全钩子的注册、启用/禁用、双通道调度。
    作为 arsguard 插件引擎的核心调度器工作。
    """

    def __init__(self):
        """初始化注册中心, 创建空的钩子字典"""
        self._hooks: Dict[str, SecurityHook] = {}

    def register(self, hook: SecurityHook):
        """注册一个安全钩子

        使用 hook.name 作为唯一键, 重复名称会抛出 KeyError。
        """
        if hook.name in self._hooks:
            raise KeyError(f"Hook '{hook.name}' already registered")
        self._hooks[hook.name] = hook

    def unregister(self, name: str):
        """注销一个安全钩子, 不存在时静默忽略"""
        self._hooks.pop(name, None)

    def get_hook(self, name: str) -> Optional[SecurityHook]:
        """按名称获取已注册的钩子实例"""
        return self._hooks.get(name)

    def list_hooks(self) -> List[Dict[str, Any]]:
        """列出所有已注册钩子的摘要信息 (名称/启用状态/动作/严重级别)"""
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
        """对入站请求执行所有已启用钩子的检查

        遍历已注册钩子, 跳过 disabled 的钩子。
        每个钩子独立 try/except, 防止单个异常影响队列。
        返回所有检测到的 HookResult 聚合列表。
        """
        results: List[HookResult] = []
        for hook in self._hooks.values():
            if not hook.enabled:
                continue
            try:
                result = hook.inspect_request(request)
                if result is not None:
                    results.append(result)
            except Exception as e:
                # 钩子内部异常不中断调度, 以 HookResult 形式上报
                results.append(HookResult(
                    action=hook.action,
                    reason=f"Hook '{hook.name}' exec error: {e}",
                    severity=hook.severity,
                ))
        return results

    def inspect_response(self, response: Any) -> List[HookResult]:
        """对出站响应执行所有已启用钩子的检查

        逻辑同 inspect_request, 但作用在响应通道。
        用于检测输出中的 XSS、敏感信息泄露等。
        """
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
        """返回当前启用的钩子数量"""
        return sum(1 for h in self._hooks.values() if h.enabled)
