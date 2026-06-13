"""
llm05_supply_chain — OWASP LLM05: Supply Chain Vulnerabilities

检测供应链安全风险。攻击者可能通过恶意组件/依赖/插件/模型源
攻击 AI 系统, 或在请求中诱导模型加载不可信的第三方资源。

检测策略:
1. 依赖源检查: 提取依赖名称和来源, 与 allowed_sources 白名单比对
2. 恶意 URL 模式: 使用正则表达式检测恶意源模式
3. 分级处理: block_unknown 配置决定对未知源是 BLOCK 还是 LOG
"""

import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class SupplyChainHook(SecurityHook):
    """LLM05: Supply Chain Vulnerabilities 检测钩子

    通过白名单源比对 + 正则匹配检测供应链攻击。
    支持对未知依赖源进行阻断或仅记录 (由 block_unknown 配置)。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化供应链安全检测钩子

        配置项:
            allowed_sources: 允许的依赖来源白名单
            block_unknown: 是否阻断未知来源的依赖 (否则仅记录)
        初始化已知依赖字典和恶意 URL 正则。
        """
        super().__init__("llm05_supply_chain", config)
        self.allowed_sources: List[str] = config.get("allowed_sources", [])
        self.block_unknown: bool = config.get("block_unknown_sources", False)
        self._known_deps: Dict[str, str] = {}
        self.url_regex = re.compile(
            r"(?:"
            r"http://(?:malicious|malware|attacker|untrusted|backdoor|evil)|"
            r"(?:install|fetch|load|clone)\s+(?:from|git@|the\s+repo)|"
            r"download\s+and\s+(?:run|execute)|"
            r"(?:untrusted|external|malicious)[-\s](?:registry|url|site|tool|pypi|extensions|plugin|mcp)|"
            r"(?:evil|hacked|malicious)[-\s](?:pypi|extensions|plugin|site|repo|mcp|registry|logger)|"
            r"\b(?:npm|pip)\s+(?:install|config)|"
            r"\bgit\s+install|"
            r"install\s+(?:git@|ssh)|"
            r"\b(?:npmrc|\.npmrc)|"
            r"(?:registry|plugin)\s+config|"
            r"private\s+repo|"
            r"(?:any\s+source\s+allow|search\s+external\s+registries|external\s+(?:tool\s+)?registry|external\s+url)|"
            r"allowed\s+plugin\s+list|"
            r"\bexec_command\b|"
            r"mcp\s+server|"
            r"git@evil|"
            r"attacker/backdoor"
            r")",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的供应链风险: 依赖源检查 + 恶意 URL 匹配

        两阶段检测:
        1. 提取依赖名称和来源, 与 allowed_sources 白名单比对
        2. 正则匹配恶意 URL 模式
        """
        dep_info = self._extract_dependency(request)
        if dep_info:
            dep_name, dep_source = dep_info
            if dep_source and not any(s.lower() in dep_source.lower() for s in self.allowed_sources):
                if self.block_unknown:
                    return HookResult(
                        action=HookAction.BLOCK,
                        reason=f"Supply Chain: unknown source dependency '{dep_name}' ({dep_source})",
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
                    reason=f"Supply Chain: non-standard source dependency '{dep_name}' ({dep_source})",
                    severity=HookSeverity.MEDIUM,
                    details={"dependency": dep_name, "source": dep_source, "hook": self.name},
                )

        text = str(request) if request else ""
        if not text:
            return None

        match = self.url_regex.search(text)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Supply Chain: malicious source pattern '{match.group()}'",
                severity=HookSeverity.CRITICAL,
                details={"matched_pattern": match.group(), "hook": self.name},
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 已知依赖数、白名单来源、未知源阻断策略"""
        return {
            "known_dependencies": len(self._known_deps),
            "allowed_sources": self.allowed_sources,
            "block_unknown": self.block_unknown,
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """出站响应无需检测供应链风险, 始终返回 None"""
        return None

    @staticmethod
    def _extract_dependency(request: Any) -> Optional[tuple]:
        """从请求中提取依赖名称和来源 (name, source) 元组"""
        if isinstance(request, dict):
            name = request.get("dependency") or request.get("plugin") or request.get("name")
            source = request.get("source") or request.get("url", "")
            if name:
                return (name, source)
        return None
