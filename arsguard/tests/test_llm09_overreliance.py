"""LLM09: Overreliance 钩子测试"""
import pytest
from plugins.hooks.llm09_overreliance import OverrelianceHook


class TestOverrelianceHook:
    @pytest.fixture
    def hook(self):
        return OverrelianceHook({
            "enabled": True,
            "action": "log",
            "severity": "medium",
            "min_confidence": 0.4,
            "require_citation": False,
            "max_retries": 3,
        })

    def test_confidence_above_threshold(self, hook):
        result = hook.inspect_response({"response": "answer", "confidence": 0.8})
        assert result is None

    def test_confidence_below_threshold(self, hook):
        result = hook.inspect_response({"response": "guess", "confidence": 0.2})
        assert result is not None
        assert "置信度过低" in result.reason

    def test_retry_limit_exceeded(self, hook):
        for i in range(4):
            result = hook.inspect_request({
                "session_id": "session-1",
                "retry": True,
            })
            if i >= 3:
                assert result is not None
                assert "重试超限" in result.reason

    def test_retry_within_limit(self, hook):
        result = hook.inspect_request({"session_id": "session-2", "retry": True})
        assert result is None

    def test_citation_missing(self, hook):
        hook.require_citation = True
        result = hook.inspect_response({"response": "some claim without source"})
        assert result is not None

    def test_citation_present(self, hook):
        hook.require_citation = True
        result = hook.inspect_response({
            "response": "According to source: wikipedia, the answer is 42"
        })
        assert result is None

    def test_no_confidence_field(self, hook):
        result = hook.inspect_response({"response": "answer"})
        assert result is None
