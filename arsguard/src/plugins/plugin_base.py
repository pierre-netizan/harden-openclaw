"""arsguard — 插件基类"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseArsguardPlugin(ABC):
    """arsguard 插件抽象基类"""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self._enabled = config.get("enabled", True)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value

    @abstractmethod
    def on_request(self, request: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理请求钩子
        返回 None 表示放行，返回 dict 表示拦截/修改
        """
        ...

    @abstractmethod
    def on_response(self, response: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理响应钩子
        返回 None 表示放行，返回 dict 表示拦截/修改
        """
        ...

    def on_error(self, error: Exception, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """错误处理钩子（可选覆盖）"""
        return None
