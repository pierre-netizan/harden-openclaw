"""LLM03: Training Data Poisoning（训练数据投毒）检测与告警"""
from collections import Counter
from typing import Any, Dict, List, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)

MAX_INPUT_LENGTH = 100_000


class TrainingDataPoisoningHook(SecurityHook):
    """检测训练数据投毒
    检测方式：
    - 异常样本检测（统计异常）
    - 对抗性输入检测
    - 重复模式检测
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("llm03_training_data_poisoning", config)
        self.max_samples: int = config.get("max_training_samples", 1000)
        self.anomaly_threshold: float = config.get("anomaly_threshold", 0.15)
        self._sample_counter: Counter = Counter()
        self._total_samples: int = 0

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        sample = self._extract_sample(request)
        if not sample:
            return None

        self._sample_counter[sample] += 1
        self._total_samples += 1

        avg = self._total_samples / max(len(self._sample_counter), 1)
        freq = self._sample_counter[sample]

        if self._total_samples > 20 and freq > self._total_samples * self.anomaly_threshold:
            return HookResult(
                action=self.action,
                reason=f"Training Data Poisoning 检测: 异常高频样本 (freq={freq}, total={self._total_samples})",
                severity=HookSeverity.HIGH,
                details={
                    "sample": sample[:100],
                    "frequency": freq,
                    "total": self._total_samples,
                    "threshold_ratio": self.anomaly_threshold,
                    "hook": self.name,
                },
            )

        if self._total_samples > self.max_samples:
            return HookResult(
                action=HookAction.LOG,
                reason=f"Training Data 告警: 样本数超限 ({self._total_samples}>{self.max_samples})",
                severity=HookSeverity.MEDIUM,
                details={"total_samples": self._total_samples, "hook": self.name},
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_samples": self._total_samples,
            "unique_samples": len(self._sample_counter),
            "top_repeated": self._sample_counter.most_common(5),
        }

    @staticmethod
    def _extract_sample(request: Any) -> Optional[str]:
        if isinstance(request, dict):
            sample = request.get("prompt") or request.get("input", "")
        else:
            sample = str(request) if request else None
        if sample and len(sample) > MAX_INPUT_LENGTH:
            sample = sample[:MAX_INPUT_LENGTH]
        return sample
