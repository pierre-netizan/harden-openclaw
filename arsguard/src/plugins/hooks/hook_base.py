"""arsguard — 安全钩子基类"""
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class HookAction(Enum):
    BLOCK = "block"
    LOG = "log"
    REPORT = "report"


class HookSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HookResult:
    """钩子处理结果"""

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
        return self.action == HookAction.BLOCK

    def should_log(self) -> bool:
        return self.action in (HookAction.LOG, HookAction.BLOCK, HookAction.REPORT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "details": self.details,
        }


class SecurityHook(ABC):
    """安全钩子抽象基类"""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self._enabled = config.get("enabled", True)
        self.action = HookAction(config.get("action", "block"))
        self.severity = HookSeverity(config.get("severity", "medium"))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @abstractmethod
    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检查请求，返回 None 表示安全"""
        ...

    @abstractmethod
    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检查响应，返回 None 表示安全"""
        ...


class BasePatternHook(SecurityHook):
    """基于模式匹配的安全钩子基类"""

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.patterns: List[str] = config.get("patterns", [])
        self.filter_patterns: List[str] = config.get("filter_patterns", [])

    def _match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        """检查文本是否匹配任意模式"""
        text_lower = text.lower()
        matched = []
        for pattern in patterns:
            if pattern.lower() in text_lower:
                matched.append(pattern)
        return matched
