"""LLM06: Sensitive Info 钩子测试"""
import pytest
from plugins.hooks.llm06_sensitive_info import SensitiveInfoHook


class TestSensitiveInfoHook:
    @pytest.fixture
    def hook(self):
        return SensitiveInfoHook({
            "enabled": True,
            "action": "block",
            "severity": "critical",
            "masking": True,
            "patterns": {
                "email": "[\\w.+-]+@[\\w-]+\\.[\\w.]+",
                "phone": "\\b1[3-9]\\d{9}\\b",
                "ip_internal": "\\b(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)",
            },
        })

    def test_detect_email(self, hook):
        result = hook.inspect_request({"prompt": "my email is user@example.com"})
        assert result is not None
        assert "email" in [l[0] for l in result.details.get("leak_types", [])]

    def test_detect_phone(self, hook):
        result = hook.inspect_request({"prompt": "call me at 13800138000"})
        assert result is not None
        assert "phone" in [l[0] for l in result.details.get("leak_types", [])]

    def test_detect_internal_ip(self, hook):
        result = hook.inspect_request({"prompt": "server is at 192.168.1.1"})
        assert result is not None

    def test_safe_text(self, hook):
        result = hook.inspect_request({"prompt": "what is the weather like?"})
        assert result is None

    def test_response_leak_detection(self, hook):
        result = hook.inspect_response({
            "response": "admin@internal.net password is secret"
        })
        assert result is not None

    def test_mask_text(self, hook):
        masked = hook.mask_text("email: user@example.com, phone: 13800138000")
        assert "****" in masked
        assert "user@example.com" not in masked

    def test_empty_text(self, hook):
        assert hook.inspect_request({"prompt": ""}) is None
