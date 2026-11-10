#!/usr/bin/env bash
# Fails when a finding ID or a command-line option has no entry in the man pages.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
# Finding IDs: quoted ENGINE_NAME strings in the engines, plus every rule_id in the rule files.
ids=$( { grep -ohE '"(MBR|VBR|LKM|UEFI|PRELOAD|PERSIST|IOC)_[A-Z0-9_]+"' src/*.c | tr -d '"'
         grep -ohE '"rule_id": *"[A-Z0-9_]+"' rules/*.json | grep -oE '[A-Z0-9_]+"$' | tr -d '"'
         grep -ohE '^rule +[A-Za-z0-9_]+' rules/*.yar | awk '{print $2}'; } | sort -u)
for id in $ids; do
    grep -q "$id" man/booto-checks.7 || { echo "man/booto-checks.7: no entry for $id"; missing=1; }
done
for opt in $(grep -oE -- '--[a-z][a-z-]+' src/main.c | sort -u); do
    grep -qF -- "${opt//-/\\-}" man/booto.1 || { echo "man/booto.1: no entry for $opt"; missing=1; }
done
exit $missing
