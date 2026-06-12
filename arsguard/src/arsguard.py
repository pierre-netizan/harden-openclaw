#!/usr/bin/env python3
"""arsguard — AI Agent 安全加固入口
作为 OpenClaw 插件加载时的入口点
"""
import os
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:
    yaml = None


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """加载 arsguard 配置"""
    if config_path is None:
        config_path = os.environ.get(
            "ARSGUARD_CONFIG",
            "/etc/arsguard/arsguard.yaml",
        )

    default_config = {
        "enabled": True,
        "ollama": {
            "host": "http://localhost:11434",
            "target_model": "qwen3-0.6b",
            "prompt_model": "Qwen/Qwen3-4B-Instruct-2507",
        },
        "hooks": {},
    }

    if not os.path.exists(config_path):
        return default_config

    if yaml is None:
        return default_config

    try:
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}
        merged = {**default_config, **user_config}
        merged["hooks"] = {**default_config.get("hooks", {}), **user_config.get("hooks", {})}
        return merged
    except Exception:
        return default_config


def create_plugin(config_path: Optional[str] = None):
    """创建 arsguard 插件实例（OpenClaw 插件加载入口）"""
    config = load_config(config_path)
    from .plugins.arsguard_plugin import ArsguardPlugin
    return ArsguardPlugin(config)
