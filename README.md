# harden-openclaw

harden-openclaw 是 OpenClaw LLM 网关的安全加固方案，由两个独立子项目组成：

- **[arsguard](https://github.com/pierre-netizan/arsguard)** — OpenClaw 安全插件，提供 OWASP Top 10 for AI Agents 实时检测与拦截
- **[eval](https://github.com/pierre-netizan/eval)** — 安全测试框架，提供多周期自动化测试流水线

## 快速开始

```bash
git clone --recurse-submodules git@github.com:pierre-netizan/harden-openclaw.git
cd harden-openclaw
# 子模块会自动克隆到 arsguard/ 和 eval/
```

## 子模块

| 路径 | 仓库 | 说明 |
|------|------|------|
| `arsguard/` | [pierre-netizan/arsguard](https://github.com/pierre-netizan/arsguard) | 安全插件：10 个检测钩子 + Squid 部署 |
| `eval/` | [pierre-netizan/eval](https://github.com/pierre-netizan/eval) | 测试框架：四周期引擎 + 稳定性检查 |

## 版本管理

使用 `cd eval && ./check_tag.sh` 一键完成：跑测试 → 检查 bypass 率 → 提交子模块 + 父模块 → 打 tag → 推送到 GitHub。Tag 格式 `v0.1.N`，当连续 5 轮 bypass 率 ≤ 阈值时自动创建。
