"""
hook_base — arsguard 安全钩子基类与数据类型

提供所有 OWASP Top 10 for AI Agents 安全钩子的抽象基类 (SecurityHook),
模式匹配基类 (BasePatternHook), 以及通用结果/枚举类型 (HookResult,
HookAction, HookSeverity)。

设计策略:
- SecurityHook 定义 inspect_request / inspect_response 双通道检测接口
- BasePatternHook 提供 size-limited substring 模式匹配, 防 regex DoS
- HookResult 统一携带 action/reason/severity/details, 供调度层决策
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class HookAction(Enum):
    """钩子触发后的处置动作枚举

    - BLOCK: 拦截请求/响应, 阻止继续传递
    - LOG:   仅记录告警, 不阻断
    - REPORT: 上报但不阻断 (预留用于 SIEM 集成)
    """
    BLOCK = "block"
    LOG = "log"
    REPORT = "report"


class HookSeverity(Enum):
    """安全事件严重级别枚举, 从低到高"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HookResult:
    """钩子检测结果, 包含处置动作、原因、严重级别和详细信息"""

    def __init__(
        self,
        action: HookAction,
        reason: str,
        severity: HookSeverity = HookSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.action = action
        self.reason = reason
        self.severity = severity
        self.details = details or {}

    def should_block(self) -> bool:
        """是否需要阻断: 仅 action == BLOCK 时返回 True"""
        return self.action == HookAction.BLOCK

    def should_log(self) -> bool:
        """是否需要记录日志: BLOCK / LOG / REPORT 均需日志"""
        return self.action in (HookAction.LOG, HookAction.BLOCK, HookAction.REPORT)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典, 供 JSON 序列化或日志输出"""
        return {
            "action": self.action.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "details": self.details,
        }


class SecurityHook(ABC):
    """安全钩子抽象基类

    所有 OWASP Top 10 for AI Agents 钩子的共同父类。
    子类需实现 inspect_request 和 inspect_response 方法,
    返回 HookResult (检测到风险) 或 None (安全)。

    配置驱动: enabled / action / severity 均来自 arsguard.yaml。
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self._enabled = config.get("enabled", True)
        self.action = HookAction(config.get("action", "block"))
        self.severity = HookSeverity(config.get("severity", "medium"))

    @property
    def enabled(self) -> bool:
        """钩子是否启用 (配置中的 enabled 字段)"""
        return self._enabled

    @abstractmethod
    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检查入站请求, 返回 HookResult 表示检测到风险, None 表示安全"""
        ...

    @abstractmethod
    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检查出站响应, 返回 HookResult 表示检测到风险, None 表示安全"""
        ...


class BasePatternHook(SecurityHook):
    """基于大/小写不敏感 substring 匹配的安全钩子基类

    适用于以固定关键词列表检测风险的场景 (如 Prompt Injection、XSS)。
    使用 substring 而非 regex 避免 ReDoS 攻击。
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Args:
            name: 钩子名称, 用于唯一标识和日志
            config: 配置字典, 支持以下键:
                - patterns: 需要匹配的危险模式列表
                - filter_patterns: 需要过滤的豁免模式列表
        """
        super().__init__(name, config)
        self.patterns: List[str] = config.get("patterns", [])
        self.filter_patterns: List[str] = config.get("filter_patterns", [])

    def _match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        """substring 匹配: 返回所有在 text 中出现的模式

        遍历 pattern 列表, 对每个 pattern 做 case-insensitive substring 检查。
        返回所有匹配到的模式名称, 供 HookResult.reason 使用。
        """
        text_lower = text.lower()
        matched = []
        for pattern in patterns:
            if pattern.lower() in text_lower:
                matched.append(pattern)
        return matched
