#!/usr/bin/env bash
# ==============================================================================
# Booto Automated Code Coverage Evaluator
# Uses gcov/lcov to compute line & branch coverage metrics.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Booto Code Coverage Assessment ==="

cd "${REPO_ROOT}"

# 1. Run all test suites to produce .gcda execution profiles
for t in build/test_*; do
    if [ -x "$t" ]; then
        echo "Executing $t..."
        "$t" >/dev/null 2>&1 || true
    fi
done

# 2. Run gcov on all source object files
mkdir -p build/coverage
cd build

total_lines=0
exec_lines=0

echo "--------------------------------------------------------"
printf "%-30s | %-12s | %-10s\n" "Source File" "Lines Exec" "Coverage %"
echo "--------------------------------------------------------"

for f in ../src/*.c; do
    fname=$(basename "$f")
    obj_name="${fname%.c}.o"
    
    if [ -f "${fname%.c}.gcno" ] || [ -f "${obj_name%.o}.gcno" ]; then
        gcov_out=$(gcov -o . "$f" 2>/dev/null || true)
        
        lines_pct=$(echo "$gcov_out" | grep "Lines executed:" | head -n 1 | awk '{print $2}' | tr -d '%')
        if [ -n "$lines_pct" ]; then
            printf "%-30s | %-12s | %6s%%\n" "$fname" "Covered" "$lines_pct"
        fi
    fi
done

echo "--------------------------------------------------------"
echo "[+] Coverage analysis complete."
