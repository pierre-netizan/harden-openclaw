#!/usr/bin/env bash
# arsguard — 一键部署脚本
# 安装 Ollama + 拉取模型 + Docker 部署 OpenClaw+Squid
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "  arsguard — AI Agent 安全加固部署脚本"
echo "=========================================="

# 步骤1：安装 Ollama 并拉取模型
echo ""
echo "[1/4] 安装 Ollama 并拉取模型 ..."
bash "$SCRIPT_DIR/install_ollama.sh"

# 步骤2：检查 Docker
echo ""
echo "[2/4] 检查 Docker 环境 ..."
if ! command -v docker &>/dev/null; then
  echo "错误：请先安装 Docker" >&2
  exit 1
fi
if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  echo "错误：请先安装 docker-compose" >&2
  exit 1
fi
echo "Docker 已就绪"

# 步骤3：部署 OpenClaw + Squid
echo ""
echo "[3/4] 部署 OpenClaw + Squid ..."
COMPOSE_CMD="docker compose"
if ! docker compose version &>/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
fi
$COMPOSE_CMD -f "$PROJECT_DIR/docker/docker-compose.yml" up -d --build

# 步骤4：验证部署
echo ""
echo "[4/4] 验证部署状态 ..."
sleep 5
echo ""
echo "--- Docker 容器状态 ---"
docker ps --filter "name=arsguard" --filter "name=openclaw" --filter "name=squid"

echo ""
echo "--- Ollama 模型 ---"
ollama list 2>/dev/null || echo "（Ollama 未运行）"

echo ""
echo "=========================================="
echo "  arsguard 部署完成"
echo ""
echo "  Squid 代理:      http://localhost:3128"
echo "  OpenClaw:        通过 Squid 访问"
echo "  Ollama API:      http://localhost:11434"
echo ""
echo "  测试连接:"
echo "    curl -x http://localhost:3128 http://openclaw:8080/health"
echo "=========================================="
