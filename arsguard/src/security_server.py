#!/usr/bin/env python3
"""arsguard — Python security check daemon for OpenClaw plugin.

Long-running process communicating via stdin/stdout JSON-RPC.
Receives check requests from the JS plugin wrapper, runs arsguard
security hooks, and returns allow/block verdicts.

Protocol:
  Request:  {"id": 1, "method": "check_input", "prompt": "...", ...}
  Response: {"id": 1, "allowed": true}
  Response: {"id": 1, "allowed": false, "reason": "..."}

When blocked:
- Python side: ArsguardPlugin._show_blocked_warning() prints a visible
  warning banner (box-drawn) to stderr inside the container.
- JS side: box.logger.warn() logs the block to OpenClaw's log stream.
- The response {"allowed":false} signals OpenClaw to not forward the
  blocked input to the LLM.
"""
import json
import os
import sys
import traceback

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SRC_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Import the arsguard plugin factory from the plugins package.
# Uses PARENT_DIR in sys.path to resolve the 'plugins' package correctly.
from plugins.arsguard import create_plugin, load_config


def main():
    """Main loop: read JSON-RPC requests from stdin, dispatch, write responses.

    Log format (via arsguard_plugin.py _log_result):
        time|tool|model|file|function|line|message

    Supported methods:
        check_input   — run on_request security hooks on LLM input
        check_output  — run on_response security hooks on LLM output
        get_stats     — return plugin statistics
        ping          — health check
    """
    config_path = os.environ.get("ARSGUARD_CONFIG")
    config = load_config(config_path)
    plugin = create_plugin(config_path)

    sys.stderr.write(f"[arsguard] security server started (enabled={plugin.enabled})\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")

            # check_input — 入站请求安全检测
            # 对用户提交的 LLM 输入执行所有安全钩子 (inspect_request),
            # 返回 allowed=true 表示通过, false + reason 表示被拦截。
            if method == "check_input":
                prompt = req.get("prompt", "")
                system_prompt = req.get("systemPrompt", "")
                context = {
                    "source": "openclaw_plugin",
                    "provider": req.get("provider", ""),
                    "model": req.get("model", ""),
                }
                result = plugin.on_request(prompt, context)
                if result and result.get("intercepted"):
                    response = {
                        "id": req_id,
                        "allowed": False,
                        "reason": result.get("reason", "blocked by security policy"),
                    }
                else:
                    response = {"id": req_id, "allowed": True}

            # check_demo — 轻量入站检测 (跳过 Model DoS 等有状态钩子)
            # 供仪表盘 /check 端点使用, 避免无害测试请求被限速误拦截。
            elif method == "check_demo":
                prompt = req.get("prompt", "")
                context = {
                    "source": "openclaw_plugin",
                    "provider": req.get("provider", ""),
                    "model": req.get("model", ""),
                }
                result = plugin.on_request_demo(prompt, context)
                if result and result.get("intercepted"):
                    response = {
                        "id": req_id,
                        "allowed": False,
                        "reason": result.get("reason", "blocked by security policy"),
                    }
                else:
                    response = {"id": req_id, "allowed": True}

            # check_output — 出站响应安全检测
            # 对 LLM 输出执行安全钩子 (inspect_response),
            # 检测 XSS/JS 注入、敏感信息泄露等。
            elif method == "check_output":
                text = req.get("text", "")
                context = {
                    "source": "openclaw_plugin",
                    "provider": req.get("provider", ""),
                    "model": req.get("model", ""),
                }
                result = plugin.on_response(text, context)
                if result and result.get("intercepted"):
                    response = {
                        "id": req_id,
                        "allowed": False,
                        "reason": result.get("reason", "blocked by security policy"),
                    }
                else:
                    response = {"id": req_id, "allowed": True}

            # get_stats — 返回插件运行时统计信息
            # 包括总拦截数、日志数、各钩子命中次数、状态等。
            elif method == "get_stats":
                response = {"id": req_id, "stats": plugin.get_stats()}

            # ping — 健康检查接口
            # 返回 {"pong": true} 确认守护进程存活。
            elif method == "ping":
                response = {"id": req_id, "pong": True}

            # 未知方法 — 返回错误响应
            else:
                response = {"id": req_id, "error": f"unknown method: {method}"}

        except Exception as e:
            tb = traceback.format_exc()
            sys.stderr.write(f"[arsguard] error processing request: {e}\n{tb}\n")
            sys.stderr.flush()
            response = {"id": req.get("id"), "error": str(e)}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
