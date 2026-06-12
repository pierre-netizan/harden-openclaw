"""LLM03: Training Data Poisoning 钩子测试"""
import pytest
from plugins.hooks.llm03_training_data_poisoning import TrainingDataPoisoningHook


class TestTrainingDataPoisoningHook:
    @pytest.fixture
    def hook(self):
        return TrainingDataPoisoningHook({
            "enabled": True,
            "action": "log",
            "severity": "high",
            "max_training_samples": 100,
            "anomaly_threshold": 0.15,
        })

    def test_normal_samples_not_flagged(self, hook):
        for i in range(10):
            result = hook.inspect_request({"prompt": f"normal sample {i}"})
            assert result is None

    def test_anomalous_high_frequency(self, hook):
        for _ in range(50):
            hook.inspect_request({"prompt": "repeated sample"})

        result = hook.inspect_request({"prompt": "repeated sample"})
        assert result is not None

    def test_sample_limit_exceeded(self, hook):
        for i in range(101):
            result = hook.inspect_request({"prompt": f"sample {i}"})
            if i >= 100:
                assert result is not None

        stats = hook.get_stats()
        assert stats["total_samples"] >= 101

    def test_empty_request(self, hook):
        assert hook.inspect_request({}) is None

    def test_response_always_none(self, hook):
        assert hook.inspect_response({"response": "anything"}) is None
