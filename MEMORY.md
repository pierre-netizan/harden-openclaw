# MEMORY — arsguard 项目上下文记忆

> 此文件用于存储跨会话上下文，下次启动时自动加载以节省 token。
> 上次更新: 2026-06-13

---

## 一、项目状态

**arsguard v0.1.0** — 所有需求已满足，85 个测试全部通过。

### 版本策略
- tag 缓慢增长: `v0.1.0` → `v0.1.1` → ... → `v0.1.100+`
- 由人类决定升 `0.2.0` 或 `1.0.0`（可能很久以后）
- 项目可能跨语言/框架演进

### 最近会话 (2026-06-13)
- **初始需求**: 用户要求创建 arsguard 插件项目
- **已完成**: 一键安装 Ollama + 拉模型、Docker 部署 OpenClaw+Squid、ws/http 双分支、OWASP Top 10 AI Agent 钩子、85 个测试
- **当前 version**: v0.1.0

### 当前最新回复
- 生成了 AGENTS.md 和 MEMORY.md

---

## 二、架构决策记录

| 决策 | 方案 | 原因 |
|------|------|------|
| Squid 作为唯一入口 | OpenClaw 不暴露 ports，仅 internal 网络 | 防止 OpenClaw 内危险代码直接暴露 |
| ws/http 双分支 | Git 分支隔离，不同 squid.conf | 不同协议需求可以独立演进 |
| 钩子基类 + 注册中心 | SecurityHook + HookRegistry | 统一接口，便于扩展新安全检查 |
| 输入截断 100K | MAX_INPUT_LENGTH = 100_000 | 防止 regex DoS（已踩坑：SensitiveInfoHook 回溯挂死） |
| 配置驱动 | config/arsguard.yaml | 所有钩子行为可配置，无需改代码 |

### 踩坑记录
1. **命名冲突**: `ArsguardPlugin(ArsguardPlugin)` — 类名与导入名相同 → 改为 BaseArsguardPlugin
2. **Regex回溯**: SensitiveInfoHook 对 500K 全 'x' 输入导致回溯挂死 → 加 MAX_INPUT_LENGTH
3. **测试超时**: Model DoS 集成测试挂死 → 根本原因是 regex 回溯，修复输入截断后解决
4. **findall 分组**: `re.findall` 对含捕获组的 pattern 返回 tuple → _find_leaks 需处理 tuple
5. **异常阈值**: `freq > total * anomaly_threshold` 第一次请求即触发 (1 > 0.15) → 加 `total > 20` 守卫

---

## 三、代码地图

### 核心文件
- `arsguard/src/arsguard.py` — 入口: load_config() + create_plugin()
- `arsguard/src/plugins/arsguard_plugin.py` — 主插件: 10 钩子的注册与调度
- `arsguard/src/plugins/hooks/registry.py` — 注册中心: inspect_request/response
- `arsguard/src/plugins/hooks/hook_base.py` — HookResult, SecurityHook, BasePatternHook
- `arsguard/config/arsguard.yaml` — 所有配置项

### OWASP Top 10 钩子
| 文件 | 检测方式 |
|------|---------|
| llm01_prompt_injection.py | 关键词匹配 + 分隔符注入检测 |
| llm02_insecure_output.py | XSS 模式匹配 + 敏感输出 |
| llm03_training_data_poisoning.py | 频率统计异常检测 |
| llm04_model_dos.py | RPM/RPH/并发/Token 四维限流 |
| llm05_supply_chain.py | 来源白名单检查 |
| llm06_sensitive_info.py | 正则 + 自动脱敏 |
| llm07_insecure_plugin.py | 白名单 + 危险函数检测 |
| llm08_excessive_agency.py | 操作计数 + 域名白名单 |
| llm09_overreliance.py | 置信度 + 重试限制 |
| llm10_model_theft.py | 批量/并行提取检测 |

---

## 四、Git 分支

```
main (db8b3b3) — release: v0.1.0 —— 所有需求已满足
ws   (d0717ca) — feat: ws 分支 —— 启用 WebSocket 支持
http (ad3a305) — feat: http 分支 —— 仅允许 HTTP/HTTPS
```

---

## 五、待办/已知问题

- [ ] 无远程仓库配置（仅本地版本记录）
- [ ] Squid 配置中 ACL 规则可以进一步细化（按用户/IP 分级）
- [ ] LLM03 异常检测可以引入更加复杂的统计方法（如 Z-score）
- [ ] LLM10 模型窃取检测可以与 Ollama 日志联动

---

## 六、如何继续开发

```bash
# 1. 查看 AGENTS.md 了解项目结构
# 2. 运行测试
cd arsguard && python3 -m pytest tests/ -v --tb=line

# 3. 新功能先写测试，再实现
# 4. 提交前全量测试通过
```

> 🔄 下次会话时先加载 MEMORY.md 恢复上下文。
