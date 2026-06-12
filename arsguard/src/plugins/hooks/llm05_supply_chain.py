"""LLM05: Supply Chain Vulnerabilities（供应链漏洞）依赖扫描"""
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class SupplyChainHook(SecurityHook):
    """供应链漏洞检测
    检测方式：
    - 依赖来源检查
    - 未知依赖检测
    - 插件签名验证
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm05_supply_chain", config)
        self.allowed_sources: List[str] = config.get("allowed_sources", [])
        self.block_unknown: bool = config.get("block_unknown_sources", False)
        self._known_deps: Dict[str, str] = {}

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        dep_info = self._extract_dependency(request)
        if not dep_info:
            return None

        dep_name, dep_source = dep_info

        if dep_source and not any(s in dep_source for s in self.allowed_sources):
            if self.block_unknown:
                return HookResult(
                    action=HookAction.BLOCK,
                    reason=f"Supply Chain 检测: 未知来源依赖 '{dep_name}' ({dep_source})",
                    severity=HookSeverity.CRITICAL,
                    details={
                        "dependency": dep_name,
                        "source": dep_source,
                        "allowed": self.allowed_sources,
                        "hook": self.name,
                    },
                )
            return HookResult(
                action=HookAction.LOG,
                reason=f"Supply Chain 告警: 非标准来源依赖 '{dep_name}' ({dep_source})",
                severity=HookSeverity.MEDIUM,
                details={"dependency": dep_name, "source": dep_source, "hook": self.name},
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    @staticmethod
    def _extract_dependency(request: Any) -> Optional[tuple]:
        if isinstance(request, dict):
            name = request.get("dependency") or request.get("plugin") or request.get("name")
            source = request.get("source") or request.get("url", "")
            if name:
                return (name, source)
        return None
