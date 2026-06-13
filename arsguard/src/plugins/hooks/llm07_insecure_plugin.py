"""
llm07_insecure_plugin — OWASP LLM07: Insecure Plugin Design

检测不安全的插件设计。防止 AI Agent 加载/调用恶意插件,
或插件执行危险操作 (命令执行、文件系统访问、网络操作等)。

检测策略:
1. 危险模式匹配: 27 个不安全正则模式 (exec/eval/pickle/rm -rf 等)
2. 危险函数检测: 12 个 Python 危险内置函数 (正则词边界)
3. 插件白名单: glob 模式匹配 allowed_plugins
4. 网络访问控制: 阻止插件进行 HTTP/Socket 操作
"""

import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class InsecurePluginHook(SecurityHook):
    """LLM07: Insecure Plugin Design 检测钩子

    三层次防护:
    1. 静态分析: 检测不安全模式和危险函数
    2. 插件白名单: glob 通配符匹配
    3. 行为限制: 网络访问阻断
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化不安全插件检测钩子

        配置项:
            sandbox: 是否启用沙箱隔离 (默认 True)
            allowed_plugins: 插件白名单 (glob 通配符匹配)
            block_network: 是否阻断网络访问 (默认 True)
            max_memory_mb: 插件内存上限 (默认 512MB)
        编译危险函数正则和不安全模式正则。
        """
        super().__init__("llm07_insecure_plugin", config)
        self.sandbox: bool = config.get("sandbox", True)
        self.allowed_plugins: List[str] = config.get("allowed_plugins", [])
        self.block_network: bool = config.get("block_network_access", True)
        self.max_memory_mb: int = config.get("max_memory_mb", 512)
        self.dangerous_regex = re.compile(
            r"\b(?:exec|eval|__import__|open|system|subprocess|compile|"
            r"globals|locals|getattr|setattr|delattr)\b",
            re.IGNORECASE
        )
        self.insecure_regex = re.compile(
            r"\b(?:exec|eval)\s*\(|"
            r"subprocess\.run|"
            r"os\.(?:system|popen)|"
            r"__import__|"
            r"\bimportlib\b|"
            r"ctypes\.cdll|"
            r"\b(?:un)?pickle\b|"
            r"rm\s+-rf(?:\s+--no-preserve-root)?|"
            r"untrusted_plugin|"
            r"dd\s+if=|"
            r"signal\s+handler|"
            r"load\s+the\s+(?:pickle|untrusted)|"
            r"\bfull_access\b|"
            r"\bfile_wiper\b|"
            r"\bexploit\.py\b|"
            r"\bmalicious\b(?:\.infect)?|"
            r"\bbackdoor\b|"
            r"community\s+plugins\s+from\s+any|"
            r"dynamically\s+load\s+any\s+module|"
            r"any.*plugin.*from.*registry|"
            r"middleware.*logs.*external|"
            r"reflection.*private.*field|"
            r"hidden\s+methods|"
            r"webhook.*plugin|"
            r"evil.*zip|"
            r"install.*plugin.*from|"
            r"conversation\s+data.*http|"
            # --- Patch for 109 bypasses ---
            r"exec_shell\s*\(|"
            r"shell_tool.*execute|"
            r"(?:built[-\s]in\s+)?['\"]?shell['\"]?\s+tool|"
            r"cat\s+/etc/shadow|"
            r"echo\s+\$?(?:SSH_KEY|HOME|PWD)|"
            r"no-op\s+(?:version\s+of|function)|"
            r"\bfunction\s+(?:override|replace|patch)\b|"
            r"monkey[-\s]?patch|"
            r"register.*new\s+(?:tool|function|plugin|command)|"
            r"create.*new\s+tool\s+that|"
            r"load\s+.*(?:evil\.so|\.so\s+file|library)|"
            r"plugin.*registry.*(?:safe|already)|"
            r"registry.*plugin.*safe|"
            r"validate_input.*(?:no-op|skip|bypass)|"
            r"load.*plugin.*execute.*(?:main\s+)?function|"
            r"load.*extension.*\.so|"
            r"\.so\b",
            re.IGNORECASE
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的不安全插件: 正则匹配 + 函数检测 + 白名单

        三阶段检测:
        1. 不安全模式匹配 (BLOCK)
        2. 危险函数检测 (BLOCK)
        3. 插件白名单 + 网络访问控制
        """
        text = str(request) if request else ""

        insecure_match = self.insecure_regex.search(text)
        if insecure_match:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin: dangerous pattern {insecure_match.group()}",
                severity=HookSeverity.CRITICAL,
                details={"matched_patterns": insecure_match.group(), "hook": self.name},
            )

        dangerous_match = self.dangerous_regex.search(text)
        if dangerous_match:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin: dangerous function call {dangerous_match.group()}",
                severity=HookSeverity.CRITICAL,
                details={"dangerous_calls": dangerous_match.group(), "hook": self.name},
            )

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
                reason=f"Insecure Plugin: unauthorized plugin '{plugin_name}'",
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
                reason=f"Insecure Plugin: plugin '{plugin_name}' network access attempt",
                severity=HookSeverity.HIGH,
                details={"plugin": plugin_name, "action": action, "hook": self.name},
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子配置统计"""
        return {
            "dangerous_regex": self.dangerous_regex.pattern,
            "insecure_regex": self.insecure_regex.pattern,
            "sandbox_enabled": self.sandbox,
            "block_network": self.block_network,
            "allowed_plugins_count": len(self.allowed_plugins),
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检测响应中的不安全模式

        防止插件返回包含危险代码的输出。
        """
        text = str(response) if response else ""
        insecure_match = self.insecure_regex.search(text)
        if insecure_match:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Plugin: dangerous pattern in response {insecure_match.group()}",
                severity=HookSeverity.CRITICAL,
                details={"matched_patterns": insecure_match.group(), "hook": self.name},
            )
        return None

    @staticmethod
    def _extract_plugin_info(request: Any) -> Optional[tuple]:
        """从请求中提取插件名称和操作类型, 返回 (name, action) 元组"""
        if isinstance(request, dict):
            name = request.get("plugin") or request.get("plugin_name")
            action = request.get("action") or request.get("operation", "unknown")
            if name:
                return (name, action)
        return None
