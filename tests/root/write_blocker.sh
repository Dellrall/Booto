#!/bin/sh
# Root only: checks assets/udev/booto-ro makes a disk read-only. Usage: sudo sh tests/root/write_blocker.sh
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
img=$(mktemp)
trap 'losetup -d "$dev" 2>/dev/null; rm -f "$img"' EXIT
dd if=/dev/urandom of="$img" bs=1M count=4 status=none
dev=$(losetup -f --show "$img")
before=$(sha256sum < "$dev")
sh "$here/assets/udev/booto-ro" "$dev"
[ "$(blockdev --getro "$dev")" = 1 ] || { echo "FAIL: $dev not read-only"; exit 1; }
if dd if=/dev/zero of="$dev" bs=512 count=1 conv=notrunc status=none 2>/dev/null; then echo "FAIL: write succeeded"; exit 1; fi
[ "$(sha256sum < "$dev")" = "$before" ] || { echo "FAIL: contents changed"; exit 1; }
echo "PASS: $dev read-only, write refused, hash unchanged"
