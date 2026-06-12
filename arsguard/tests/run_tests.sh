#!/usr/bin/env bash
# arsguard — 运行全部测试
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "  arsguard 测试套件"
echo "=========================================="

# 安装依赖
pip install -q pyyaml jsonschema pytest pytest-cov 2>/dev/null || true

# 运行测试
python -m pytest tests/ -v --cov=src/plugins --cov-report=term-missing "$@"

echo ""
echo "=========================================="
echo "  测试完成"
echo "=========================================="
