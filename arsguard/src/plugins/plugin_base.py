"""arsguard — 插件基类.

提供所有 arsguard 插件的抽象基类。每个插件必须实现 on_request 和 on_response
两个拦截方法, 并在生命周期内管理自身的启用/禁用状态。
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseArsguardPlugin(ABC):
    """arsguard 插件抽象基类

    定义插件生命周期契约: 每个插件必须实现 on_request 和 on_response 方法。
    基类管理启用/禁用状态和插件配置。

    Attributes:
        name: 插件唯一名称 (如 "arsguard").
        version: 插件版本号.
        description: 插件描述文本.
        config: 原始配置字典.
    """

    VERSION = "0.0.0"
    DESCRIPTION = ""

    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize the plugin with a name and configuration.

        Args:
            name: Plugin identifier, used for logging and routing.
            config: Configuration dict; the top-level "enabled" key controls
                whether the plugin is active.
        """
        self.name = name
        self.version = self.VERSION
        self.description = self.DESCRIPTION
        self.config = config
        self._enabled = config.get("enabled", True)

    @property
    def enabled(self) -> bool:
        """Return whether the plugin is currently enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Enable or disable the plugin at runtime."""
        self._enabled = value

    @abstractmethod
    def on_request(self, request: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Intercept an inbound (request) payload.

        Every subclass must implement this method. Return None to allow
        the request through, or a dict to block or modify it.

        Args:
            request: The raw incoming request (typically a prompt string).
            context: Metadata dict (source IP, headers, etc.).

        Returns:
            None to allow, or a dict with interception details.
        """
        ...

    @abstractmethod
    def on_response(self, response: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Intercept an outbound (response) payload.

        Every subclass must implement this method. Return None to allow
        the response through, or a dict to block or modify it.

        Args:
            response: The raw outgoing response (typically model-generated text).
            context: Metadata dict (model name, latency, etc.).

        Returns:
            None to allow, or a dict with interception details.
        """
        ...

    def on_error(self, error: Exception, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle exceptions raised during request/response processing.

        Optional override — the default implementation returns None (ignore).

        Args:
            error: The exception that was raised.
            context: Metadata dict relevant to the failed operation.

        Returns:
            None to continue without intervention, or a dict to intercept.
        """
        return None
