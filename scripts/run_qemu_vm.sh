#!/usr/bin/env bash
# ==============================================================================
# Booto Automated QEMU Virtual Machine Testbed
# Boots the Live ISO with a synthetic rootkit-infected target disk attached.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ISO_PATH="${1:-${REPO_ROOT}/dist/booto-live-amd64.iso}"
DISK_IMG="/tmp/booto_mock_target.img"

echo "======================================================================"
echo "          BOOT TO FORENSICS (BOOT) - QEMU VM TESTBED                  "
echo "======================================================================"

# 1. Check if QEMU is installed
if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "[!] QEMU is not installed on this system."
    echo "[+] To install QEMU & KVM on Debian/Ubuntu, run:"
    echo "    sudo apt-get update && sudo apt-get install -y qemu-system-x86 ovmf"
    exit 1
fi

# 2. Check if Live ISO exists, build if missing
if [ ! -f "${ISO_PATH}" ]; then
    echo "[+] Live ISO not found at ${ISO_PATH}. Building fresh ISO..."
    sudo "${REPO_ROOT}/scripts/build_iso.sh"
fi

# 3. Create synthetic rootkit test drive if missing
if [ ! -f "${DISK_IMG}" ]; then
    echo "[+] Creating 500MB synthetic rootkit test disk at ${DISK_IMG}..."
    "${REPO_ROOT}/scripts/gen_mock_disk.sh" "${DISK_IMG}" 500
fi

# 4. Check for KVM acceleration
KVM_FLAG=""
if [ -w /dev/kvm ]; then
    echo "[+] Hardware virtualization (KVM) enabled."
    KVM_FLAG="-enable-kvm"
fi

# 5. Locate UEFI firmware (OVMF)
OVMF_FLAG=""
if [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF_FLAG="-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd"
    echo "[+] UEFI (OVMF) firmware detected."
fi

echo "[+] Launching Booto VM (RAM: 2048 MB, Cores: 2)..."
echo "[+] Primary Boot:  ${ISO_PATH}"
echo "[+] Target Drive:  ${DISK_IMG}"
echo "======================================================================"

qemu-system-x86_64 \
    ${KVM_FLAG} \
    -m 2048 \
    -smp 2 \
    -cdrom "${ISO_PATH}" \
    -boot d \
    -drive file="${DISK_IMG}",format=raw,index=1,media=disk \
    ${OVMF_FLAG} \
    -vga std \
    -display gtk
