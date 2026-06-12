"""LLM08: Excessive Agency 钩子测试"""
import pytest
from plugins.hooks.llm08_excessive_agency import ExcessiveAgencyHook


class TestExcessiveAgencyHook:
    @pytest.fixture
    def hook(self):
        return ExcessiveAgencyHook({
            "enabled": True,
            "action": "block",
            "severity": "high",
            "max_allowed_actions": 5,
            "allowed_domains": ["api.openclaw.ai"],
            "block_exec_command": True,
            "block_file_write": True,
        })

    def test_normal_actions_allowed(self, hook):
        for i in range(5):
            result = hook.inspect_request({
                "agent_id": "agent-1",
                "action": f"query_{i}",
            })
            assert result is None

    def test_exceeds_max_actions(self, hook):
        agent = "agent-2"
        for i in range(6):
            result = hook.inspect_request({
                "agent_id": agent,
                "action": f"action_{i}",
            })
            if i >= 5:
                assert result is not None
                assert "操作次数超限" in result.reason

    def test_exec_command_blocked(self, hook):
        result = hook.inspect_request({
            "agent_id": "agent-3",
            "action": "exec_command",
        })
        assert result is not None
        assert result.should_block()

    def test_file_write_blocked(self, hook):
        result = hook.inspect_request({
            "agent_id": "agent-4",
            "action": "file_write",
        })
        assert result is not None

    def test_unauthorized_domain(self, hook):
        result = hook.inspect_request({
            "agent_id": "agent-5",
            "action": "http_request",
            "domain": "https://evil.com",
        })
        assert result is not None
        assert "未授权域名" in result.reason

    def test_authorized_domain(self, hook):
        result = hook.inspect_request({
            "agent_id": "agent-6",
            "action": "http_request",
            "domain": "api.openclaw.ai",
        })
        assert result is None

    def test_no_action(self, hook):
        assert hook.inspect_request({"agent_id": "agent-7"}) is None
