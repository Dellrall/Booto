#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <version.h.in> <version.h> [version_string]" >&2
    exit 1
fi

VERSION_IN="$1"
VERSION_OUT="$2"
PROJECT_VERSION="${3:-0.0.0-unknown}"

GIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Parse SemVer (non-numeric parts default to 0)
IFS=. read -r MAJOR MINOR PATCH _ <<< "${PROJECT_VERSION}." || true
MAJOR="$(printf '%s' "${MAJOR:-}" | tr -cd '0-9')"
MINOR="$(printf '%s' "${MINOR:-}" | tr -cd '0-9')"
PATCH="$(printf '%s' "${PATCH:-}" | sed 's/[^0-9].*//')"
MAJOR="${MAJOR:-0}"
MINOR="${MINOR:-0}"
PATCH="${PATCH:-0}"

mkdir -p "$(dirname "$VERSION_OUT")"

sed -e "s/@PROJECT_VERSION@/${PROJECT_VERSION}/g" \
    -e "s/@PROJECT_VERSION_MAJOR@/${MAJOR}/g" \
    -e "s/@PROJECT_VERSION_MINOR@/${MINOR}/g" \
    -e "s/@PROJECT_VERSION_PATCH@/${PATCH}/g" \
    -e "s/@GIT_COMMIT_HASH@/${GIT_HASH}/g" \
    -e "s/@BUILD_TIMESTAMP@/${BUILD_DATE}/g" \
    "$VERSION_IN" > "$VERSION_OUT"

echo "Generated $VERSION_OUT (Version: $PROJECT_VERSION, Git: $GIT_HASH)"
