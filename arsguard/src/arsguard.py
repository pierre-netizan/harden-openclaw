#!/usr/bin/env python3
"""arsguard — AI Agent 安全加固入口.

Entry point for loading arsguard as an OpenClaw plugin.
Handles configuration loading (YAML with fallback defaults)
and plugin instance creation.
"""
import os
from typing import Any, Dict, Optional

__version__ = "0.1.0"

try:
    import yaml
except ImportError:
    yaml = None


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load and merge arsguard configuration from a YAML file.

    Resolution order:
        1. Use the provided config_path, or
        2. Fall back to the ARSGUARD_CONFIG environment variable, or
        3. Use the default path /etc/arsguard/arsguard.yaml.

    If the file is missing, unreadable, or YAML is not installed, a
    sensible default configuration is returned. User-supplied keys are
    shallow-merged over defaults (hooks dict is deep-merged).

    Args:
        config_path: Optional explicit path to the YAML config file.

    Returns:
        Dict with keys: enabled, ollama (host/target_model/prompt_model), hooks.
    """
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
        # Shallow-merge top-level keys, deep-merge the hooks sub-dict
        merged = {**default_config, **user_config}
        merged["hooks"] = {**default_config.get("hooks", {}), **user_config.get("hooks", {})}
        return merged
    except Exception:
        return default_config


def create_plugin(config_path: Optional[str] = None):
    """Create an arsguard ArsguardPlugin instance.

    This is the canonical entry point called by OpenClaw's plugin loader.
    It loads the configuration (from path, env var, or default) and
    instantiates the main plugin class with its full hook registry.

    Args:
        config_path: Optional path to the YAML configuration file.

    Returns:
        An initialized ArsguardPlugin instance ready for request/response interception.
    """
    config = load_config(config_path)
    from .plugins.arsguard_plugin import ArsguardPlugin
    return ArsguardPlugin(config)
