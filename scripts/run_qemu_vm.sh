#!/usr/bin/env bash
# ==============================================================================
# Booto Automated QEMU Virtual Machine Testbed
# Boots the Live ISO with a synthetic rootkit-infected target disk attached.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -z "${1:-}" ]; then
    # Auto-detect latest ISO in dist/ or current directory
    LATEST_ISO=$(ls -t "${REPO_ROOT}/dist/"*.iso 2>/dev/null | head -n 1 || true)
    if [ -n "${LATEST_ISO}" ]; then
        ISO_PATH="${LATEST_ISO}"
    else
        ISO_PATH="${REPO_ROOT}/dist/booto-live-amd64.iso"
    fi
else
    ISO_PATH="$1"
fi

DISK_IMG="/tmp/booto_mock_target.img"

echo "======================================================================"
echo "          BOOT TO FORENSICS (BOOT) - QEMU VM TESTBED                  "
echo "======================================================================"

# 1. Check if QEMU is installed
if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "[!] QEMU is not installed on this system."
    echo "[+] To install QEMU on Ubuntu/Debian, run:"
    echo "    sudo apt-get update && sudo apt-get install -y qemu-system-x86 ovmf"
    exit 1
fi

# 2. Check if Live ISO exists
if [ ! -f "${ISO_PATH}" ]; then
    echo "[!] Live ISO not found at ${ISO_PATH}"
    echo "[+] Please build or specify an ISO: ./scripts/run_qemu_vm.sh <path_to_iso>"
    exit 1
fi

# 3. Create synthetic rootkit test drive if missing
if [ ! -f "${DISK_IMG}" ]; then
    echo "[+] Creating 500MB synthetic rootkit test disk at ${DISK_IMG}..."
    if [ -f "${REPO_ROOT}/scripts/gen_mock_disk.sh" ]; then
        "${REPO_ROOT}/scripts/gen_mock_disk.sh" "${DISK_IMG}" 500
    else
        dd if=/dev/zero of="${DISK_IMG}" bs=1M count=500 status=none
        mkfs.ext4 -F "${DISK_IMG}" status=none 2>/dev/null || true
    fi
fi

# 4. Check for KVM acceleration
KVM_FLAG=""
if [ -w /dev/kvm ]; then
    echo "[+] Hardware virtualization (KVM) enabled."
    KVM_FLAG="-enable-kvm"
else
    echo "[*] KVM not accessible, running in standard emulation mode."
fi

# 5. Locate UEFI firmware (OVMF)
OVMF_FLAG=""
if [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF_FLAG="-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd"
    echo "[+] UEFI (OVMF) firmware detected."
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF_FLAG="-drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/OVMF.fd"
    echo "[+] UEFI (OVMF) firmware detected."
fi

echo "[+] Launching Booto VM (RAM: 2048 MB, Cores: 2)..."
echo "[+] Primary Boot:  ${ISO_PATH}"
echo "[+] Target Drive:  ${DISK_IMG} (/dev/sda)"
echo "======================================================================"

exec qemu-system-x86_64 \
    ${KVM_FLAG} \
    -m 2048 \
    -smp 2 \
    -cdrom "${ISO_PATH}" \
    -boot d \
    -drive file="${DISK_IMG}",format=raw,index=1,media=disk \
    ${OVMF_FLAG} \
    -vga std
