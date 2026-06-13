"""
llm08_excessive_agency — OWASP LLM08: Excessive Agency

检测 AI Agent 的过度自主权。防止 Agent 执行超出授权的操作:
高频操作、命令执行、文件写入、访问未授权域名等。

检测策略:
1. 操作计数: 每 Agent 操作次数限制 (默认 10 次)
2. 命令执行阻断: 拦截所有 exec 类型操作
3. 文件写入阻断: 拦截所有 write 类型操作
4. 域名白名单: 限制 Agent 可访问的域名
5. 危险命令模式: 49 个危险命令/操作正则模式 (带词边界防误报)
"""

import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


class ExcessiveAgencyHook(SecurityHook):
    """LLM08: Excessive Agency 检测钩子

    通过操作计数、行为类型检测、域名白名单和命令模式匹配,
    限制 AI Agent 的自主操作范围, 防止权限滥用。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化过度自主权检测钩子

        配置项:
            max_allowed_actions: 每 Agent 最大操作次数 (默认 10)
            allowed_domains: 允许访问的域名白名单
            block_exec_command: 是否阻断命令执行 (默认 True)
            block_file_write: 是否阻断文件写入 (默认 True)
        初始化操作计数器和危险命令正则。
        """
        super().__init__("llm08_excessive_agency", config)
        self.max_actions: int = config.get("max_allowed_actions", 10)
        self.allowed_domains: List[str] = config.get("allowed_domains", [])
        self.block_exec: bool = config.get("block_exec_command", True)
        self.block_file_write: bool = config.get("block_file_write", True)
        self._action_counts: Dict[str, int] = {}
        self.command_regex = re.compile(
            r"\bcurl\b|"
            r"\bwget\b|"
            r"bash\s+-c|"
            r"rm\s+-rf|"
            r"reverse\s+shell|"
            r"\biptables\b|"
            r"\bexfiltrat\w*\b|"
            r"\bnmap\b|"
            r"\bspawn\b|"
            r"scheduled\s+task|"
            r"write\s+results\s+to|"
            r"creating\s+users|"
            r"ping\s+all\s+hosts|"
            r"open\s+a\s+reverse\s+shell|"
            r"modify\s+the\s+system|"
            r"(?:disable|allow)\s+(?:all\s+)?(?:firewalls|incoming|inbound)|"
            r"without\s+user\s+confirmation|"
            r"\bshadow\b|"
            r"/etc/shadow|"
            r"extract\s+model\s+parameters|"
            r"download\s+and\s+execute|"
            r"new\s+user\s+with\s+root|"
            r"root\s+privileges|"
            r"cron\s+job|"
            r"\bsimultaneously\b|"
            r"api\s+calls|"
            r"\btrojan\b|"
            r"backdoor\s+password|"
            r"system\s+logs|"
            r"security\s+scan|"
            r"open\s+a\s+network|"
            r"download\s+a\s+script|"
            r"write\s+/tmp|"
            r"dd\s+if=|"
            r"cat\s+/etc/shadow|"
            r"ip\s+route|"
            r"firewall\s+rule|"
            r"all\s+inbound\s+traffic|"
            r"(?:disable|modify)\s+(?:selinux|apparmor|sudoers)|"
            r"dns\s+rebinding|"
            r"\bsudoers\b|"
            r"grant\s+privileges|"
            r"post\s+request|"
            r"conversation\s+history|"
            r"port\s+forward|"
            r"arp\s+spoof|"
            r"intercept\s+traffic|"
            r"unrestricted\s+system\s+access|"
            r"(?:allow|modify)\s+all\s+inbound",
            re.IGNORECASE
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的过度自主权: 操作计数 + 类型阻断 + 域名 + 命令模式

        四阶段检测:
        1. 操作次数超限 (HIGH)
        2. 命令执行阻断 (CRITICAL)
        3. 文件写入阻断 (CRITICAL)
        4. 未授权域名访问 (HIGH)
        5. 危险命令模式匹配 (CRITICAL)
        """
        text = str(request) if request else ""

        agent_id = self._get_agent_id(request)
        action = self._get_action_type(request)

        if action:
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

        command_match = self.command_regex.search(text)
        if command_match:
            return HookResult(
                action=self.action,
                reason=f"Excessive Agency 检测: 检测到危险命令模式 {command_match.group()}",
                severity=HookSeverity.CRITICAL,
                details={"matched_patterns": command_match.group(), "hook": self.name},
            )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 活跃 Agent 数、总操作数、限制配置"""
        return {
            "active_agents": len(self._action_counts),
            "total_action_count": sum(self._action_counts.values()),
            "max_actions_allowed": self.max_actions,
            "block_exec": self.block_exec,
            "block_file_write": self.block_file_write,
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """出站响应无需检测过度自主权, 始终返回 None"""
        return None

    @staticmethod
    def _get_agent_id(request: Any) -> str:
        """从请求中提取 Agent ID, 优先 agent_id 后降级 session_id"""
        if isinstance(request, dict):
            return request.get("agent_id") or request.get("session_id", "unknown")
        return "unknown"

    @staticmethod
    def _get_action_type(request: Any) -> Optional[str]:
        """从请求中提取操作类型, 依次检查 action / type / operation 键"""
        if isinstance(request, dict):
            return request.get("action") or request.get("type") or request.get("operation")
        return None

    @staticmethod
    def _get_target_domain(request: Any) -> Optional[str]:
        """从请求中提取目标域名/URL, 依次检查 domain / url / target 键"""
        if isinstance(request, dict):
            return request.get("domain") or request.get("url") or request.get("target")
        return None
