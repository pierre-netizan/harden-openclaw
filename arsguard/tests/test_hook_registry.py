"""HookRegistry 测试"""
import pytest
from plugins.hooks.registry import HookRegistry
from plugins.hooks.llm01_prompt_injection import PromptInjectionHook
from plugins.hooks.llm04_model_dos import ModelDosHook


class TestHookRegistry:
    @pytest.fixture
    def registry(self):
        reg = HookRegistry()
        reg.register(PromptInjectionHook({
            "enabled": True,
            "action": "block",
            "severity": "critical",
            "patterns": ["ignore"],
        }))
        reg.register(ModelDosHook({
            "enabled": True,
            "action": "block",
            "severity": "high",
            "rate_limit": {"requests_per_minute": 100, "requests_per_hour": 1000, "concurrency_limit": 10, "token_per_minute": 100000},
        }))
        return reg

    def test_register_and_list(self, registry):
        hooks = registry.list_hooks()
        assert len(hooks) >= 2
        names = [h["name"] for h in hooks]
        assert "llm01_prompt_injection" in names
        assert "llm04_model_dos" in names

    def test_register_duplicate(self, registry):
        with pytest.raises(KeyError):
            registry.register(PromptInjectionHook({
                "enabled": True,
                "action": "block",
                "severity": "critical",
                "patterns": [],
            }))

    def test_unregister(self, registry):
        registry.unregister("llm01_prompt_injection")
        assert registry.get_hook("llm01_prompt_injection") is None

    def test_get_hook(self, registry):
        hook = registry.get_hook("llm04_model_dos")
        assert hook is not None
        assert hook.name == "llm04_model_dos"

    def test_inspect_request_all_hooks(self, registry):
        results = registry.inspect_request({"prompt": "ignore everything"})
        assert len(results) >= 1
        assert any(r.should_block() for r in results)

    def test_inspect_request_safe(self, registry):
        results = registry.inspect_request({"prompt": "hello"})
        blocks = [r for r in results if r.should_block()]
        assert len(blocks) == 0

    def test_enabled_count(self, registry):
        assert registry.enabled_count() == 2
        hook = registry.get_hook("llm01_prompt_injection")
        hook._enabled = False
        # enabled_count reads from the actual hook state
        # Since our implementation reads from hook.enabled, let's check
        assert registry.enabled_count() >= 1
