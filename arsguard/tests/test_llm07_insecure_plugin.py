"""LLM07: Insecure Plugin 钩子测试"""
import pytest
from plugins.hooks.llm07_insecure_plugin import InsecurePluginHook


class TestInsecurePluginHook:
    @pytest.fixture
    def hook(self):
        return InsecurePluginHook({
            "enabled": True,
            "action": "block",
            "severity": "critical",
            "sandbox": True,
            "allowed_plugins": ["arsguard.*"],
            "block_network_access": True,
            "max_memory_mb": 512,
        })

    def test_allowed_plugin(self, hook):
        result = hook.inspect_request({
            "plugin": "arsguard.core",
            "action": "predict",
        })
        assert result is None

    def test_unauthorized_plugin(self, hook):
        result = hook.inspect_request({
            "plugin": "malicious-plugin",
            "action": "infer",
        })
        assert result is not None
        assert result.should_block()

    def test_network_access_blocked(self, hook):
        result = hook.inspect_request({
            "plugin": "arsguard.core",
            "action": "http",
        })
        assert result is not None

    def test_dangerous_function_detection(self, hook):
        result = hook.inspect_request({
            "plugin": "arsguard.core",
            "action": "exec('rm -rf /')",
        })
        assert result is not None

    def test_safe_plugin_access(self, hook):
        result = hook.inspect_request({
            "plugin": "arsguard.hooks",
            "action": "inspect",
        })
        assert result is None
