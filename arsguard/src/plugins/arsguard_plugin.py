"""arsguard — OpenClaw 安全加固主插件"""
from typing import Any, Dict, List, Optional

from .hooks.hook_base import HookAction, HookResult
from .hooks.registry import HookRegistry
from .plugin_base import BaseArsguardPlugin


class ArsguardPlugin(BaseArsguardPlugin):
    """arsguard 主插件
    整合所有 OWASP Top 10 安全钩子，提供统一的请求/响应拦截入口
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("arsguard", config)
        self.registry = HookRegistry()
        self._init_hooks(config.get("hooks", {}))
        self._total_blocks = 0
        self._total_logs = 0

    def _init_hooks(self, hooks_config: Dict[str, Any]):
        from .hooks.llm01_prompt_injection import PromptInjectionHook
        from .hooks.llm02_insecure_output import InsecureOutputHook
        from .hooks.llm03_training_data_poisoning import TrainingDataPoisoningHook
        from .hooks.llm04_model_dos import ModelDosHook
        from .hooks.llm05_supply_chain import SupplyChainHook
        from .hooks.llm06_sensitive_info import SensitiveInfoHook
        from .hooks.llm07_insecure_plugin import InsecurePluginHook
        from .hooks.llm08_excessive_agency import ExcessiveAgencyHook
        from .hooks.llm09_overreliance import OverrelianceHook
        from .hooks.llm10_model_theft import ModelTheftHook

        hook_classes = [
            PromptInjectionHook,
            InsecureOutputHook,
            TrainingDataPoisoningHook,
            ModelDosHook,
            SupplyChainHook,
            SensitiveInfoHook,
            InsecurePluginHook,
            ExcessiveAgencyHook,
            OverrelianceHook,
            ModelTheftHook,
        ]

        for hook_cls in hook_classes:
            hook_name = hook_cls.__name__.replace("Hook", "").lower()
            config = hooks_config.get(hook_name, {})
            try:
                hook = hook_cls(hooks_config.get(hook_name, {}))
                self.registry.register(hook)
            except Exception as e:
                print(f"[arsguard] 钩子 '{hook_name}' 注册失败: {e}")

    def on_request(self, request: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        results = self.registry.inspect_request(request)
        return self._process_results(results, context)

    def on_response(self, response: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        results = self.registry.inspect_response(response)
        return self._process_results(results, context)

    def _process_results(
        self, results: List[HookResult], context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not results:
            return None

        blocks = [r for r in results if r.should_block()]
        logs = [r for r in results if r.should_log()]

        self._total_blocks += len(blocks)
        self._total_logs += len(logs)

        for result in logs:
            self._log_result(result)

        if blocks:
            return {
                "intercepted": True,
                "reason": blocks[0].reason,
                "blocks": [b.to_dict() for b in blocks],
                "total_blocks": self._total_blocks,
                "total_logs": self._total_logs,
            }

        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "hooks_enabled": self.registry.enabled_count(),
            "hooks_total": len(self.registry.list_hooks()),
            "total_blocks": self._total_blocks,
            "total_logs": self._total_logs,
            "hooks": self.registry.list_hooks(),
        }

    @staticmethod
    def _log_result(result: HookResult):
        print(
            f"[arsguard] {result.severity.value.upper():>8} | "
            f"{result.action.value:>6} | {result.reason}"
        )
