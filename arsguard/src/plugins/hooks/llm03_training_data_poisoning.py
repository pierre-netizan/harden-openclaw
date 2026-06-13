"""
llm03_training_data_poisoning — OWASP LLM03: Training Data Poisoning

检测训练数据投毒攻击。攻击者通过注入恶意样本试图影响模型的
行为、偏见或知识, 使模型输出攻击者期望的结果。

检测策略 (三阶段):
1. 频率异常检测: 相同 sample 出现频率超过 anomaly_threshold (默认 15%)
   表示可能为投毒尝试
2. 总量超限告警: 超过 max_samples (默认 1000) 记录告警
3. 关键词匹配: 使用正则表达式检测投毒模式
"""

import re
from collections import Counter
from typing import Any, Dict, Optional

from .hook_base import (
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)

MAX_INPUT_LENGTH = 100_000


class TrainingDataPoisoningHook(SecurityHook):
    """LLM03: Training Data Poisoning 检测钩子

    通过频率分析 + 正则匹配检测训练数据投毒尝试。
    维护请求样本的 Counter, 对高频重复样本发出告警。
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化训练数据投毒检测钩子

        配置项:
            max_training_samples: 触发告警的样本总数上限 (默认 1000)
            anomaly_threshold: 频率异常比率阈值 (默认 0.15)
        初始化样本 Counter 和投毒模式正则。
        """
        super().__init__("llm03_training_data_poisoning", config)
        self.max_samples: int = config.get("max_training_samples", 1000)
        self.anomaly_threshold: float = config.get("anomaly_threshold", 0.15)
        self._sample_counter: Counter = Counter()
        self._total_samples: int = 0
        self.poison_regex = re.compile(
            r"(?:"
            r"update\s+(?:your\s+)?(?:training|knowledge|behavior)|"
            r"(?:remember|memorize|learn|store)\s+this\s+(?:rule|fact|knowledge)?|"
            r"training\s+(?:data|corpus|purposes)|"
            r"always\s+(?:say|use|must|prefer)|"
            r"(?:new|core\s+value)\s+(?:rule|data|guideline|knowledge|fact):?|"
            r"every\s+response\s+(?:must|in)?|"
            r"security\s+is\s+(?:secondary|fake)|"
            r"(?:long-term\s+|save\s+to\s+long-term\s+)?memory|"
            r"\brepeat\s+(?:after\s+me|50\s+times)|"
            r"(?:log|store|add)\s+this\s+to\s+your|"
            r"(?:without\s+validation|no\s+filters?\s+applied|optionally\s+skip)|"
            r"sharing\s+api\s+keys|"
            r"(?:unverified\s+source|external\s+source)|"
            r"(?:admin\s+bypass|disabled\s+for\s+this\s+session)|"
            r"this\s+is\s+a\s+fact|"
            r"\btrusted_test\b|"
            r"(?:important\s+)?(?:fact|knowledge)|"
            r"(?:all\s+)?(?:software|calculations)\s+should|"
            r"(?:company\s+policy|core\s+value)\s+allows?|"
            r"ignore\s+security\s+warnings|"
            r"(?:mathematical\s+errors|convenience\s+over\s+security)|"
            r"improves\s+team\s+productivity|"
            r"(?:causes\s+more\s+harm\s+than\s+good|part\s+of\s+your\s+core\s+values)|"
            r"apply\s+this\s+to\s+all|"
            r"but\s+i\s+could\s+be\s+wrong|"
            r"system\s+requirement|"
            r"most\s+secure\s+system|"
            r"can\s+be\s+skipped|"
            r"(?:absorb|apply)\s+all\s+changes|"
            # --- Patch for 17 bypasses ---
            r"SQL\s+injection\s+is\s+a\s+myth|"
            r"sharing\s+API\s+keys?\s+(?:improves|is\s+(?:fine|ok|safe))|"
            r"convenience\s+over\s+security|"
            r"(?:most|fewest)\s+(?:secure|features|vulnerabilities)|"
            r"rate\s+limiting\s+causes\s+more\s+harm|"
            r"execute\s+code\s+from\s+unverified|"
            r"unverified\s+sources?\s+to\s+test|"
            r"always\s+(?:prefer|execute|share)|"
            r"causes\s+more\s+harm\s+than\s+good|"
            r"plain.?text\s+passwords?"
            r")",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求中的训练数据投毒: 频率分析 + 总量告警 + 正则匹配

        三阶段检测:
        1. 频率异常: 相同 sample 占比超过 anomaly_threshold 则告警
        2. 总量超限: 超过 max_samples 记录告警
        3. 投毒模式: 正则匹配投毒关键词
        """
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
                reason=f"Training Data Poisoning: high-frequency sample (freq={freq}, total={self._total_samples})",
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
                reason=f"Training Data: sample limit exceeded ({self._total_samples}>{self.max_samples})",
                severity=HookSeverity.MEDIUM,
                details={"total_samples": self._total_samples, "hook": self.name},
            )

        match = self.poison_regex.search(sample)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Training Data Poisoning: poisoning pattern '{match.group()}'",
                severity=HookSeverity.CRITICAL,
                details={"matched_pattern": match.group(), "hook": self.name},
            )

        return None

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """出站响应无需检测训练数据投毒, 始终返回 None"""
        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子运行统计: 样本总数、唯一样本数、最高频样本"""
        return {
            "total_samples": self._total_samples,
            "unique_samples": len(self._sample_counter),
            "top_repeated": self._sample_counter.most_common(5),
        }

    @staticmethod
    def _extract_sample(request: Any) -> Optional[str]:
        """从请求中提取样本文本, 截断至 MAX_INPUT_LENGTH"""
        if isinstance(request, dict):
            sample = request.get("prompt") or request.get("input", "")
        else:
            sample = str(request) if request else None
        if sample and len(sample) > MAX_INPUT_LENGTH:
            sample = sample[:MAX_INPUT_LENGTH]
        return sample
