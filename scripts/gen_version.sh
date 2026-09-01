#!/bin/sh
set -e

VERSION_IN="$1"
VERSION_OUT="$2"
PROJECT_VERSION="${3:-0.1.0-alpha}"

if [ -z "$VERSION_IN" ] || [ -z "$VERSION_OUT" ]; then
    echo "Usage: $0 <version.h.in> <version.h> [version_string]"
    exit 1
fi

GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)

# Parse SemVer
MAJOR=$(echo "$PROJECT_VERSION" | cut -d. -f1 | tr -cd '0-9')
MINOR=$(echo "$PROJECT_VERSION" | cut -d. -f2 | tr -cd '0-9')
PATCH=$(echo "$PROJECT_VERSION" | cut -d. -f3 | tr -cd '0-9')

[ -z "$MAJOR" ] && MAJOR=0
[ -z "$MINOR" ] && MINOR=1
[ -z "$PATCH" ] && PATCH=0

mkdir -p "$(dirname "$VERSION_OUT")"

sed -e "s/@PROJECT_VERSION@/$PROJECT_VERSION/g" \
    -e "s/@PROJECT_VERSION_MAJOR@/$MAJOR/g" \
    -e "s/@PROJECT_VERSION_MINOR@/$MINOR/g" \
    -e "s/@PROJECT_VERSION_PATCH@/$PATCH/g" \
    -e "s/@GIT_COMMIT_HASH@/$GIT_HASH/g" \
    -e "s/@BUILD_TIMESTAMP@/$BUILD_DATE/g" \
    "$VERSION_IN" > "$VERSION_OUT"

echo "Generated $VERSION_OUT (Version: $PROJECT_VERSION, Git: $GIT_HASH)"
