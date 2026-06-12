"""LLM04: Model DoS 钩子测试"""
import time
import pytest
from plugins.hooks.llm04_model_dos import ModelDosHook


class TestModelDosHook:
    @pytest.fixture
    def hook(self):
        return ModelDosHook({
            "enabled": True,
            "action": "block",
            "severity": "high",
            "rate_limit": {
                "requests_per_minute": 10,
                "requests_per_hour": 50,
                "concurrency_limit": 3,
                "token_per_minute": 10000,
            },
        })

    def test_normal_request_allowed(self, hook):
        # Use separate IPs to avoid concurrency limit
        for i in range(5):
            result = hook.inspect_request({"client_ip": f"10.0.0.{i}"})
            assert result is None

    def test_rpm_exceeded(self, hook):
        ip = "192.168.1.100"
        for i in range(11):
            result = hook.inspect_request({"client_ip": ip})
            if result is not None and i > 3:
                # First 4 may hit concurrency limit, RPM kicks in after
                if "RPM" in result.reason:
                    return
        # If RPM didn't trigger but concurrency did, that's also acceptable
        # Just verify some limit was reached
        pytest.fail("No rate limit was triggered after 11 requests")

    def test_concurrency_limit(self, hook):
        ip = "192.168.1.200"
        # Simulate 3 concurrent requests (allowed)
        for _ in range(3):
            result = hook.inspect_request({"client_ip": ip})
            assert result is None

        # 4th should be blocked
        result = hook.inspect_request({"client_ip": ip})
        assert result is not None
        assert "并发" in result.reason

    def test_concurrency_released_on_response(self, hook):
        ip = "192.168.1.300"
        hook.inspect_request({"client_ip": ip})
        hook.inspect_request({"client_ip": ip})
        hook.inspect_request({"client_ip": ip})

        hook.inspect_response({"client_ip": ip})
        # 3rd was blocked, after response, 4th might still be blocked
        # Actually let's just verify the response handler doesn't crash
        hook.inspect_response({"client_ip": ip})
        hook.inspect_response({"client_ip": ip})
        result = hook.inspect_request({"client_ip": ip})
        assert result is None  # concurrency released

    def test_token_limit(self, hook):
        ip = "192.168.1.400"
        large_request = {"client_ip": ip, "prompt": "x" * 50000}
        result = hook.inspect_request(large_request)
        assert result is not None
        assert "Token" in result.reason
