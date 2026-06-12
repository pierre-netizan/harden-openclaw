#!/usr/bin/env bash
# arsguard — 一键安装 Ollama
set -euo pipefail

echo "[arsguard] 开始安装 Ollama ..."

# 检测操作系统
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ]; then
  echo "[arsguard] 错误：当前仅支持 Linux x86_64（检测到 $OS）" >&2
  exit 1
fi

if [ "$ARCH" != "x86_64" ]; then
  echo "[arsguard] 错误：当前仅支持 x86_64 架构（检测到 $ARCH）" >&2
  exit 1
fi

# 检查是否已安装
if command -v ollama &>/dev/null; then
  echo "[arsguard] Ollama 已安装，版本：$(ollama --version 2>/dev/null || echo 'unknown')"
else
  echo "[arsguard] 下载并安装 Ollama ..."
  curl -fsSL https://ollama.com/install.sh | sh
fi

# 启动 Ollama 服务（如果未运行）
if ! pgrep -x ollama >/dev/null; then
  echo "[arsguard] 启动 Ollama 服务 ..."
  nohup ollama serve > /tmp/ollama.log 2>&1 &
  sleep 3
fi

# 等待服务就绪
echo "[arsguard] 等待 Ollama 服务就绪 ..."
for i in $(seq 1 30); do
  if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "[arsguard] Ollama 服务已就绪"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "[arsguard] 错误：Ollama 服务启动超时" >&2
    exit 1
  fi
  sleep 2
done

echo "[arsguard] Ollama 安装完成"

# 拉取模型
echo "[arsguard] 开始拉取模型 ..."

echo "  → 拉取 qwen3-0.6b（目标模型）..."
ollama pull qwen3-0.6b

echo "  → 拉取 Qwen/Qwen3-4B-Instruct-2507（提示词生成模型）..."
ollama pull Qwen/Qwen3-4B-Instruct-2507

echo "[arsguard] 所有模型拉取完成"
echo "[arsguard] 可用模型列表："
ollama list

exit 0
