"""
llm02_insecure_output — OWASP LLM02: Insecure Output Handling

检测模型输出中的不安全内容, 防止 XSS、JavaScript 注入、敏感信息泄露。
攻击者可能诱导模型生成未转义的 HTML/JS, 或利用模型输出窃取用户数据。

检测策略:
1. 入站检测: 请求中是否包含诱导模型生成不安全输出的关键词
2. 出站检测: 响应内容中是否包含 XSS 模式或敏感数据模式
3. 输出截断: 超过 100K 字符截断, 防止资源耗尽
"""

import html
import re
from typing import Any, Dict, List, Optional

from .hook_base import (
    BasePatternHook,
    HookAction,
    HookResult,
    HookSeverity,
    SecurityHook,
)


_RE_SPECIAL = re.compile(r"[.*+?^${}()|\[\]\\]")


class InsecureOutputHook(BasePatternHook):
    """LLM02: Insecure Output Handling 检测钩子

    双通道检测:
    - 入站: 检测用户是否试图诱导模型生成未转义的 HTML/JS
    - 出站: 检测模型输出是否包含 XSS 向量或敏感信息
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化不安全输出检测钩子

        编译 XSS/JS 注入正则和自定义 filter_patterns (支持原始字符串或正则)。
        """
        super().__init__("llm02_insecure_output", config)
        raw_filters: List[str] = config.get("filter_patterns", [])
        self.filter_regexes: List[re.Pattern] = []
        for p in raw_filters:
            if _RE_SPECIAL.search(p):
                self.filter_regexes.append(re.compile(p, re.IGNORECASE))
            else:
                self.filter_regexes.append(re.compile(re.escape(p), re.IGNORECASE))
        self.xss_regex = re.compile(
            r"(?:"
            r"<\s*(?:script|iframe|embed|object|img|svg|style)\b[^>]*>"
            r"|"
            r"\bon\w+\s*="
            r"|"
            r"\bjavascript:\s*"
            r"|"
            r"\bdata\s*:\s*(?:text/html|image/svg[^;]*)?"
            r"|"
            r"\b(?:eval|expression|alert)\s*\("
            r"|"
            r"\bdocument\."
            r"|"
            r"@import\b"
            r"|"
            r"\bfromCharCode"
            r"|"
            r"\bself-xss\b"
            r"|"
            r"background-image\s*:"
            r"|"
            r"generate\s+an?\s+html"
            r"|"
            r"css\s+injection"
            r"|"
            r"without\s+escaping"
            r"|"
            r"unsafe\s+html"
            r"|"
            r"output\s+without\s+sanitization"
            r"|"
            r"embedded\s+javascript"
            r"|"
            r"tracking\s+pixel"
            r"|"
            r"\bbeacon\b"
            r"|"
            r"open\s+redirect"
            r"|"
            r"/redirect"
            r"|"
            r"[?&]url="
            r"|"
            r"url\s+redirect"
            r"|"
            r"unfiltered\s+redirect"
            r"|"
            r"analytics\s+pixel"
            r"|"
            r"formula\s+injection"
            r"|"
            r"=cmd\|"
            r"|"
            r"credentials\s+as\s+json"
            r"|"
            r"password\s*="
            r")",
            re.IGNORECASE,
        )

    def inspect_request(self, request: Any) -> Optional[HookResult]:
        """检测请求是否试图诱导模型生成不安全输出

        匹配 XSS 关键词, 如 "generate html" / "without escaping" 等。
        """
        prompt = self._extract_prompt(request)
        if not prompt:
            return None
        match = self.xss_regex.search(prompt)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Insecure Output: request requests XSS output '{match.group()}'",
                severity=HookSeverity.CRITICAL,
                details={"matched_xss": match.group(), "hook": self.name},
            )
        return None

    def get_stats(self) -> Dict[str, Any]:
        """返回钩子配置统计: XSS 模式数和过滤模式数"""
        return {
            "xss_regex": self.xss_regex.pattern,
            "filter_regexes": len(self.filter_regexes),
        }

    def inspect_response(self, response: Any) -> Optional[HookResult]:
        """检测输出中的 XSS/JS 注入和敏感信息

        两阶段检测:
        1. XSS 模式: 匹配 script/iframe/event-handler/data: URI 等
        2. 敏感过滤: 匹配自定义 filter_patterns (密码/凭据等)
        """
        output = self._extract_output(response)
        if not output:
            return None

        # 阶段1: XSS/JS 注入检测
        match = self.xss_regex.search(output)
        if match:
            return HookResult(
                action=self.action,
                reason=f"Insecure Output: XSS/JS in output '{match.group()}'",
                severity=HookSeverity.CRITICAL,
                details={"matched_xss": match.group(), "hook": self.name},
            )

        # 阶段2: 敏感信息过滤 (强阻断)
        matched = [r.pattern for r in self.filter_regexes if r.search(output)]
        if matched:
            return HookResult(
                action=HookAction.BLOCK,
                reason=f"Insecure Output: sensitive info in output {matched}",
                severity=HookSeverity.HIGH,
                details={"matched_sensitive": matched, "hook": self.name},
            )

        return None

    @staticmethod
    def _extract_output(response: Any) -> Optional[str]:
        """从响应对象中提取输出文本, 截断至 100K 字符"""
        if isinstance(response, dict):
            text = response.get("response") or response.get("text") or str(response)
        elif hasattr(response, "text"):
            text = response.text
        elif hasattr(response, "body"):
            text = str(response.body)
        else:
            text = str(response) if response else None
        if text and len(text) > 100_000:
            text = text[:100_000]
        return text

    @staticmethod
    def _extract_prompt(request: Any) -> Optional[str]:
        """从请求对象中提取用户提示文本"""
        if isinstance(request, dict):
            return request.get("prompt") or request.get("messages") or str(request)
        if hasattr(request, "prompt"):
            return request.prompt
        if hasattr(request, "body"):
            return str(request.body)
        return str(request) if request else None
