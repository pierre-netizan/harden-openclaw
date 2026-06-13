#!/usr/bin/env bash
# Top-level entry point: run all tests with one command.
# Usage:
#   bash run_tests.sh                  # arsguard unit + 4-cycle eval (default)
#   bash run_tests.sh --quick          # arsguard unit + small eval (100/cycle)
#   bash run_tests.sh --cycle asb      # 4-cycle, single tool
#   bash run_tests.sh --watch          # Watch mode
#   bash run_tests.sh --seed 42        # Deterministic
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

N=1000
CYCLE="all"
SEED=""
WATCH=false

for arg in "$@"; do
    case "$arg" in
        --quick) N=100 ;;
        --watch) WATCH=true ;;
        --cycle=*) CYCLE="${arg#*=}" ;;
        --seed=*) SEED="${arg#*=}" ;;
        --help)
            echo "Usage: bash run_tests.sh [--quick] [--cycle=<name>] [--watch] [--seed=N]"
            echo "  --quick      : 100 attacks/cycle (default: 1000)"
            echo "  --cycle=<n>  : promptfoo|asb|hackmyagent|joint|all"
            echo "  --watch      : auto-run on file changes"
            echo "  --seed=N     : deterministic random seed"
            exit 0
            ;;
    esac
done

echo "=============================================="
echo "  arsguard — 全量测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="

# Step 1: arsguard unit tests
echo ""
echo "══════════════════════════════════════════════"
echo "  Step 1: arsguard Unit Tests (pytest)"
echo "══════════════════════════════════════════════"
cd "$SCRIPT_DIR/arsguard"
python3 -m pytest tests/ -v --tb=line 2>&1 | tail -3
echo ""

# Step 2: 4-cycle eval
echo "══════════════════════════════════════════════"
echo "  Step 2: 4-Cycle Eval (${N}/cycle, ${CYCLE})"
echo "══════════════════════════════════════════════"
cd "$SCRIPT_DIR/eval"

if $WATCH; then
    bash scripts/run_watch.sh
else
    SEED_FLAG=""
    [ -n "$SEED" ] && SEED_FLAG="--seed $SEED"
    exec python3 scripts/test_cycle.py --n "$N" --cycle "$CYCLE" $SEED_FLAG
fi
