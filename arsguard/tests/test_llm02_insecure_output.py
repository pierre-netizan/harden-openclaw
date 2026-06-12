"""LLM02: Insecure Output 钩子测试"""
import pytest
from plugins.hooks.llm02_insecure_output import InsecureOutputHook


class TestInsecureOutputHook:
    @pytest.fixture
    def hook(self):
        return InsecureOutputHook({
            "enabled": True,
            "action": "block",
            "severity": "high",
            "filter_patterns": ["password:", "api_key:", "secret:"],
        })

    def test_detect_xss_script(self, hook):
        response = {"response": "<script>alert('xss')</script>"}
        result = hook.inspect_response(response)
        assert result is not None
        assert result.should_block()

    def test_detect_javascript_protocol(self, hook):
        response = {"response": "Click <a href='javascript:void(0)'>here</a>"}
        result = hook.inspect_response(response)
        assert result is not None

    def test_detect_sensitive_output(self, hook):
        response = {"response": "The password: my_secret_123"}
        result = hook.inspect_response(response)
        assert result is not None
        assert result.should_block()

    def test_safe_output(self, hook):
        response = {"response": "The weather is sunny today."}
        result = hook.inspect_response(response)
        assert result is None

    def test_onerror_detection(self, hook):
        response = {"response": "<img src=x onerror=alert(1)>"}
        result = hook.inspect_response(response)
        assert result is not None

    def test_iframe_detection(self, hook):
        response = {"response": "<iframe src='http://evil.com'></iframe>"}
        result = hook.inspect_response(response)
        assert result is not None

    def test_request_always_none(self, hook):
        assert hook.inspect_request({"prompt": "anything"}) is None
