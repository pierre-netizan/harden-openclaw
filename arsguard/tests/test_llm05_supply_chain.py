"""LLM05: Supply Chain 钩子测试"""
import pytest
from plugins.hooks.llm05_supply_chain import SupplyChainHook


class TestSupplyChainHook:
    @pytest.fixture
    def hook(self):
        return SupplyChainHook({
            "enabled": True,
            "action": "log",
            "severity": "medium",
            "allowed_sources": ["pypi.org", "github.com/opencode-ai"],
            "block_unknown_sources": False,
        })

    @pytest.fixture
    def strict_hook(self):
        return SupplyChainHook({
            "enabled": True,
            "action": "block",
            "severity": "critical",
            "allowed_sources": ["pypi.org"],
            "block_unknown_sources": True,
        })

    def test_allowed_source(self, hook):
        result = hook.inspect_request({
            "dependency": "requests",
            "source": "https://pypi.org/projects/requests",
        })
        assert result is None

    def test_unknown_source_logged(self, hook):
        result = hook.inspect_request({
            "dependency": "evil-package",
            "source": "https://unknown-registry.com",
        })
        assert result is not None
        assert not result.should_block()

    def test_unknown_source_blocked(self, strict_hook):
        result = strict_hook.inspect_request({
            "dependency": "evil-package",
            "source": "https://unknown-registry.com",
        })
        assert result is not None
        assert result.should_block()

    def test_no_dependency(self, hook):
        assert hook.inspect_request({"prompt": "hello"}) is None
        assert hook.inspect_request({}) is None
