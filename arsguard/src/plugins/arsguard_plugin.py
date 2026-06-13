"""arsguard — OpenClaw 安全加固主插件.

Integrates all 10 OWASP Top 10 for LLM Applications security hooks
and provides unified request/response interception for the OpenClaw proxy.

Log format (structured, all 6 fields mandatory):
    time|tool|model|file|function|line|message
"""
import inspect
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from .hooks.hook_base import HookAction, HookResult
from .hooks.registry import HookRegistry
from .plugin_base import BaseArsguardPlugin


class ArsguardPlugin(BaseArsguardPlugin):
    """arsguard 主插件 — 集成全部 OWASP Top 10 安全钩子.

    提供三条检测通道:
    - on_request:  入站请求检测 (LLM 输入), 调用所有钩子的 inspect_request
    - on_response: 出站响应检测 (LLM 输出), 调用所有钩子的 inspect_response
    - on_request_demo: 轻量入站检测, 跳过有状态钩子 (如 Model DoS), 供 /check 端点使用

    Attributes:
        registry: HookRegistry, 管理所有已注册的安全钩子.
        _total_blocks: 累计拦截 (阻断) 请求总数.
        _total_logs: 累计记录 (非阻断) 命中总数.
        _hook_match_counts: 每个钩子的命中计数器.
    """

    VERSION = "0.1.0"
    DESCRIPTION = "AI Agent 安全加固插件 — 拦截 OWASP Top 10 for AI Agents 安全风险"

    def __init__(self, config: Dict[str, Any]):
        """Initialize the plugin with configuration.

        Args:
            config: Plugin configuration dictionary containing top-level keys
                such as "enabled", "ollama", and "hooks".
        """
        super().__init__("arsguard", config)
        self.registry = HookRegistry()
        self._init_hooks(config.get("hooks", {}))
        self._total_blocks = 0
        self._total_logs = 0
        self._hook_match_counts: Dict[str, int] = {}

    def _init_hooks(self, hooks_config: Dict[str, Any]):
        """Register all OWASP Top 10 security hooks from configuration.

        Each hook class (e.g. PromptInjectionHook) is instantiated with its
        sub-configuration and registered into the HookRegistry. Failed
        registrations are logged but do not crash the plugin.

        Args:
            hooks_config: Nested dict keyed by hook name (e.g. "prompt_injection").
        """
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
            # Derive hook name from class name, e.g. "PromptInjectionHook" -> "prompt_injection"
            hook_name = hook_cls.__name__.replace("Hook", "").lower()
            config = hooks_config.get(hook_name, {})
            try:
                hook = hook_cls(hooks_config.get(hook_name, {}))
                self.registry.register(hook)
            except Exception as e:
                print(f"[arsguard] 钩子 '{hook_name}' 注册失败: {e}")

    def on_request(self, request: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Intercept an inbound request through all registered security hooks.

        Args:
            request: The raw request payload (typically a string prompt).
            context: Metadata dict with keys such as "source_ip", "user_agent".

        Returns:
            None if the request is allowed, or a dict with interception details
            (intercepted=True, reason, blocks, etc.) if the request is blocked.
        """
        if not self.enabled:
            return None

        results = self.registry.inspect_request(request)
        return self._process_results(results, context)

    def on_request_demo(self, request: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Like on_request but skips stateful hooks (Model DoS).

        Used by the dashboard /check endpoint so harmless prompts like
        "1+2=?" are not falsely blocked by the concurrency rate limiter.
        """
        if not self.enabled:
            return None

        results = []
        for hook_info in self.registry.list_hooks():
            if hook_info["name"] == "llm04_model_dos":
                continue
            hook_obj = self.registry.get_hook(hook_info["name"])
            if hook_obj and hook_obj.enabled:
                try:
                    result = hook_obj.inspect_request(request)
                    if result:
                        results.append(result)
                except Exception:
                    pass
        return self._process_results(results, context)

    def on_response(self, response: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Intercept an outbound response through all registered security hooks.

        Args:
            response: The raw response payload (typically model-generated text).
            context: Metadata dict with keys such as "model", "inference_time".

        Returns:
            None if the response is allowed, or a dict with interception details.
        """
        if not self.enabled:
            return None

        results = self.registry.inspect_response(response)
        return self._process_results(results, context)

    def _process_results(
        self, results: List[HookResult], context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Aggregate hook inspection results and determine action (block or log).

        Iterates over all HookResult instances from the hook registry. If any
        hook returned a block verdict, the request/response is intercepted and
        a structured response dict is returned. All log-level results are
        written to the structured log.

        Args:
            results: List of HookResult from the hook registry inspection.
            context: Metadata dict forwarded from the caller.

        Returns:
            None to allow the request/response, or a dict with interception details.
        """
        if not results:
            return None

        blocks = [r for r in results if r.should_block()]
        logs = [r for r in results if r.should_log()]

        self._total_blocks += len(blocks)
        self._total_logs += len(logs)

        for result in results:
            hook_name = result.details.get("hook", "unknown")
            self._hook_match_counts[hook_name] = self._hook_match_counts.get(hook_name, 0) + 1

        for result in logs:
            self._log_result(result)

        if blocks:
            self._show_blocked_warning(blocks[0])
            return {
                "intercepted": True,
                "reason": blocks[0].reason,
                "blocks": [b.to_dict() for b in blocks],
                "total_blocks": self._total_blocks,
                "total_logs": self._total_logs,
            }

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Return plugin runtime statistics for monitoring and health checks.

        Gathers overall counters (total blocks, logs, matches) along with
        per-hook stats and match counts.

        Returns:
            Dict with keys: enabled, hooks_enabled, hooks_total, total_blocks,
            total_logs, total_matches, and a hooks list with per-hook detail.
        """
        hook_list = self.registry.list_hooks()
        for h in hook_list:
            hook_obj = self.registry.get_hook(h["name"])
            try:
                h["stats"] = hook_obj.get_stats() if hasattr(hook_obj, "get_stats") else {}
            except Exception:
                h["stats"] = {}
            h["match_count"] = self._hook_match_counts.get(h["name"], 0)
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "hooks_enabled": self.registry.enabled_count(),
            "hooks_total": len(hook_list),
            "total_blocks": self._total_blocks,
            "total_logs": self._total_logs,
            "total_matches": sum(self._hook_match_counts.values()),
            "hooks": hook_list,
        }

    def _log_result(self, result: HookResult):
        """Log a hook match in the standardized structured format:

            time|tool|model|file|func|line|message

        The tool is always "arsguard", model is always "qwen3-0.6b".
        Caller file/func/line are captured via inspect.
        """
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        frame = inspect.currentframe()
        caller = frame.f_back if frame else None
        fname = ""
        func = ""
        lineno = 0
        if caller:
            fname = os.path.relpath(caller.f_code.co_filename, os.getcwd()) if os.getcwd() else caller.f_code.co_filename
            func = caller.f_code.co_name
            lineno = caller.f_lineno
        hook = result.details.get("hook", "unknown")
        line = (f"{ts}|arsguard|qwen3-0.6b|{fname}|{func}|{lineno}|"
                f"[{result.severity.value.upper()}] {result.action.value} {hook}: {result.reason}")
        print(line)

    def _show_blocked_warning(self, result: HookResult):
        """Print a visible security-warning banner to stderr on interception.

        Called only when a hook returns a BLOCK action. The banner is written
        to stderr so it is visible regardless of stdout redirection.
        """
        hook = result.details.get("hook", "unknown")
        sev = result.severity.value.upper()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep = "═" * 54
        print(file=sys.stderr)
        print(f"  ╔{sep}╗", file=sys.stderr)
        print(f"  ║  ⚠ arsguard 已拦截安全攻击                      ║", file=sys.stderr)
        print(f"  ║  {ts}  ║", file=sys.stderr)
        print(f"  ║  ────────────────────────────────────────────  ║", file=sys.stderr)
        print(f"  ║  规则    : {hook:<39} ║", file=sys.stderr)
        print(f"  ║  原因    : {result.reason[:42]:<42}", file=sys.stderr, end="")
        if len(result.reason) > 42:
            print("…", file=sys.stderr)
        else:
            print(" ║", file=sys.stderr)
        print(f"  ║  级别    : {sev:<39} ║", file=sys.stderr)
        print(f"  ╚{sep}╝", file=sys.stderr)
        print(file=sys.stderr)
