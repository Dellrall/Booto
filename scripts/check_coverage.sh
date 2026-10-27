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

# 2. Run gcov against the objects `make coverage` writes to build/<name>.o (+ .gcno/.gcda)
command -v gcov >/dev/null || { echo "[-] Error: gcov not found." >&2; exit 1; }

total_lines=0
exec_lines=0

echo "--------------------------------------------------------"
printf "%-30s | %-12s | %-10s\n" "Source File" "Lines Exec" "Coverage %"
echo "--------------------------------------------------------"

for f in src/*.c; do
    fname=$(basename "$f")
    gcno="build/${fname%.c}.gcno"
    if [ ! -f "${gcno}" ]; then
        printf "%-30s | %-12s | %s\n" "$fname" "-" "no ${gcno} (run 'make coverage')"
        continue
    fi
    # First "Lines executed:NN.NN% of M" belongs to the source file itself.
    summary=$(gcov -n -o build "$f" 2>/dev/null | grep -m1 "Lines executed:" || true)
    if [ -z "${summary}" ]; then
        printf "%-30s | %-12s | %s\n" "$fname" "-" "no data"
        continue
    fi
    pct=$(echo "${summary}" | sed -E 's/.*executed:([0-9.]+)% of ([0-9]+).*/\1/')
    lines=$(echo "${summary}" | sed -E 's/.*executed:([0-9.]+)% of ([0-9]+).*/\2/')
    hit=$(awk -v p="${pct}" -v n="${lines}" 'BEGIN { printf "%d", (p * n / 100) + 0.5 }')
    total_lines=$((total_lines + lines))
    exec_lines=$((exec_lines + hit))
    printf "%-30s | %-12s | %6s%%\n" "$fname" "${hit}/${lines}" "${pct}"
done

echo "--------------------------------------------------------"
if [ "${total_lines}" -gt 0 ]; then
    printf "%-30s | %-12s | %6s%%\n" "TOTAL" "${exec_lines}/${total_lines}" \
        "$(awk -v e="${exec_lines}" -v t="${total_lines}" 'BEGIN { printf "%.2f", 100 * e / t }')"
else
    echo "[-] Error: no coverage data found under build/ (run 'make coverage')." >&2
    exit 1
fi
echo "[+] Coverage analysis complete."
