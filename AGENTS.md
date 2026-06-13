# arsguard — AI Agent 配置

## 项目概述
arsguard 是 OpenClaw 的安全加固插件，集成 Ollama 模型服务 + Squid 反向代理，
实现安全隔离的 AI Agent 服务架构，拦截 OWASP Top 10 for AI Agents 安全风险。

## 技术栈
- **语言**: Python 3.10+
- **依赖**: pyyaml, jsonschema, pytest, promptfoo
- **部署**: Docker Compose (`docker/`), Ollama
- **模型**: qwen3-0.6b (目标), Qwen/Qwen3-4B-Instruct-2507 (提示词生成)
- **测试流水线**: eval 项目 — 三阶段 (Gen → Eval → Report)

## Git 分支策略
| 分支 | 用途 | Squid 规则 |
|------|------|-----------|
| `main` | 通用基础 | 全量配置 |
| `ws` | WebSocket 通信 | 支持 CONNECT/WebSocket 升级 |
| `http` | HTTP-only | 禁止 WebSocket，限制 CONNECT |

## 目录结构
```
docker/                           # OpenClaw + Squid 容器编排
├── docker-compose.yml
├── openclaw/Dockerfile
└── squid/
    ├── Dockerfile
    ├── http/squid.conf
    └── ws/squid.conf
arsguard/
├── config/arsguard.yaml          # 插件配置
├── scripts/
│   ├── install_ollama.sh
│   └── setup.sh                  # 一键部署
├── src/
│   ├── arsguard.py               # 插件入口
│   └── plugins/
│       ├── plugin_base.py
│       ├── arsguard_plugin.py    # 主插件
│       └── hooks/
│           ├── hook_base.py
│           ├── registry.py
│           ├── llm01_prompt_injection.py ~ llm10_model_theft.py
└── tests/                        # 85 tests, all pass
```

## eval 项目（独立测试框架）

```
eval/                               # arsguard 安全测试框架
├── check_tag.sh                    # 一键稳定性检查 + 版本提交
├── config/eval.yaml                # 主配置
├── lib/                            # 共享库
├── runners/                        # Runner 插件扩展
├── gen/                            # 攻击生成
├── eval/                           # 拦截测试
├── report/                         # 报告生成
├── config/promptfoo/               # promptfoo 配置
├── scripts/                        # 运行脚本
├── docker/                         # 测试环境 Docker 编排
└── data/                           # 输出目录 (gitignored)
```

## 快速上手指南

### 手动测试（固定任务）

用户发命令就跑，支持多轮次和参数配置：

```bash
# 跑 1 轮完整测试（4 周期 + 结果分析）
bash eval/scripts/run_round.sh

# 跑 5 轮（适合批量验证）
bash eval/scripts/run_round.sh --rounds 5

# 每周期 500 攻击，跑 3 轮
bash eval/scripts/run_round.sh --rounds 3 --n 500

# 仅分析最近一轮，不跑测试
bash eval/scripts/run_round.sh --analyze

# 跑 2 轮但不自动分析
bash eval/scripts/run_round.sh --rounds 2 --no-analyze
```

### 定时任务（Scheduled task）

系统在固定时间自动运行测试，无需人为介入：

```bash
# 设置每天凌晨 2:00 自动测试
bash eval/scripts/setup_cron.sh --daily

# 设置每周一凌晨 2:00
bash eval/scripts/setup_cron.sh --weekly

# 每小时跑一次（快速监控）
bash eval/scripts/setup_cron.sh --hourly

# 自定义 cron 表达式（周一到周五凌晨 3:00）
bash eval/scripts/setup_cron.sh --custom "0 3 * * 1-5"

# 查看已安装的定时任务
bash eval/scripts/setup_cron.sh --status

# 移除定时任务
bash eval/scripts/setup_cron.sh --remove
```

### 版本提交（当 bypass rate 稳定后）

一键操作：跑 5 轮测试 → 检查稳定性 → 达标则自动 `git commit + git tag`：

```bash
cd eval

# 默认跑 5 轮，全部 bypass ≤ 5% 则自动提交版本
./check_tag.sh

# 指定阈值（如 3%）
./check_tag.sh --threshold 3

# 自定义轮次和攻击数
./check_tag.sh --rounds 3 --n 500

# 仅查看结果，不跑测试不打 tag
./check_tag.sh --dry-run --no-run

# 使用 --help 查看更多选项
./check_tag.sh --help
```

## 关键命令
```bash
# 运行单元测试
cd arsguard && python3 -m pytest tests/ -v

# 一键部署
bash arsguard/scripts/setup.sh

# 仅安装 Ollama + 拉模型
bash arsguard/scripts/install_ollama.sh

# 切换分支
git checkout ws    # WebSocket 模式
git checkout http  # HTTP-only 模式

# ===== 安全测试流水线 =====

# 一键版本提交：跑 5 轮 → 检查 → commit + tag
cd eval && ./check_tag.sh                                   # 默认 ≤5%
cd eval && ./check_tag.sh --threshold 3                     # ≤3% 才提交
cd eval && ./check_tag.sh --rounds 3 --n 500                # 3 轮，每周期 500

# 手动测试（固定任务）：1 轮完整 4 周期测试 + 结果分析
bash eval/scripts/run_round.sh                              # 跑 1 轮
bash eval/scripts/run_round.sh --rounds 5                   # 跑 5 轮
bash eval/scripts/run_round.sh --rounds 3 --n 500           # 3 轮，每周期 500 攻击
bash eval/scripts/run_round.sh --rounds 2 --seed 42 --no-analyze  # 不分析
bash eval/scripts/run_round.sh --analyze                    # 仅分析最后一轮

# 单轮测试（run_round.sh 内部调用）
bash eval/scripts/run.sh --mode all                         # 4 周期
bash eval/scripts/run.sh --mode promptfoo --n 1000          # 仅 promptfoo
bash eval/scripts/run.sh --mode asb --seed 42               # 仅 ASB 固定种子
bash eval/scripts/run.sh --round 3                          # 指定轮次编号

# 结果分析
python3 eval/scripts/round_analyzer.py --round 1            # 分析 data-results/round1/
python3 eval/scripts/round_analyzer.py --round 1 --fp       # 含误报分析
python3 eval/scripts/round_analyzer.py --round 1 --json     # JSON 输出

# 定时任务（cron）
bash eval/scripts/setup_cron.sh --daily                     # 每天 02:00 自动测试
bash eval/scripts/setup_cron.sh --weekly                    # 每周一 02:00
bash eval/scripts/setup_cron.sh --hourly                    # 每小时
bash eval/scripts/setup_cron.sh --remove                    # 移除 cron 任务
bash eval/scripts/setup_cron.sh --status                    # 查看状态
```

## 输出目录结构
```
data-results/
├── round1/                          # 第一轮测试
│   ├── logs/                        # 全部日志 (time|tool|model|file|func|line)
│   │   ├── cycle_combined.log
│   │   ├── promptfoo.log
│   │   ├── asb.log
│   │   ├── hackmyagent.log
│   │   └── joint.log
│   ├── promptfoo/  (gen/  eval/  report/)
│   ├── asb/        (gen/  eval/  report/)
│   ├── hackmyagent/ (gen/  eval/  report/)
│   └── joint/      (gen/  eval/  report/)
├── round2/
└── ...
```

## 架构要点
- **Squid 为唯一入口**: OpenClaw 不暴露端口，外界只能通过 Squid:3128 访问
- **OWASP Top 10**: 10 个独立钩子，每个支持 enable/disable + block/log/report
- **输入安全**: 所有钩子对输入截断 100K 字符，防止 regex DoS
- **配置驱动**: 所有钩子行为通过 `config/arsguard.yaml` 控制

## 版本管理
- **tag 格式**: `v0.1.N`（N 从 0 开始，缓慢增长，可达 0.1.100+）
- **主版本升级**（由人类决定）:
  - `0.2.0` — 人类判断功能足够丰富时
  - `1.0.0` — 项目成熟稳定后才打
- **tag 时机**: 自动或手动。使用 `check_tag.sh` 自动检查 bypass rate 稳定性
- **自动化打 tag 条件**:
  - bypass rate 连续 5 轮 ≤ 用户设定的阈值（如 5%）
  - 5 轮 = 5 × 4 周期 = 20 次测试 (promptfoo, asb, hackmyagent, joint)
  - 满足条件后自动创建 `v0.1.N` tag（N 自动递增）
- 示例: `v0.1.0` → `v0.1.1` → ... → `v0.1.87` → (人类决定) → `v0.2.0`

### 自动打 tag

```bash
cd eval

# 检查最近 5 轮，全部 ≤5% 则自动 commit + tag
./check_tag.sh --threshold 5

# 指定检查轮数（如 3 轮）
./check_tag.sh --threshold 3 --rounds 3

# 仅查看结果，不创建 tag
./check_tag.sh --threshold 5 --dry-run

# 手动指定 tag 名称
./check_tag.sh --threshold 5 --tag "v0.1.42"

# 完整工作流：跑 5 轮 → 检查 → 打 tag
bash eval/scripts/run_round.sh --rounds 5 --n 1000
cd eval && ./check_tag.sh --threshold 5
```

## 开发规范
- 新功能必须有对应测试
- 提交前运行全量测试 `python3 -m pytest tests/ -v --tb=line`
- commit message 格式: `feat/fix: <描述>`
- 项目可能跨语言/框架演进，代码结构可随时重构
