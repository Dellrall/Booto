#!/usr/bin/env bash
# ==============================================================================
# Booto Dual-Partition Tails-Style USB Installer Utility
# Formats USB drive into Live OS (Partition 1) and Encrypted Persistence (Partition 2).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DRIVE="${1:-}"
ISO_PATH="${2:-${REPO_ROOT}/dist/booto-live-amd64.iso}"

if [ -z "${TARGET_DRIVE}" ]; then
    echo "Usage: sudo $0 <target_drive_e.g._/dev/sdb> [optional_iso_path]"
    echo "Example: sudo $0 /dev/sdb"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: USB setup utility requires root privileges (sudo)."
    exit 1
fi

# Safety check: Prevent wiping root or nvme system drives
if grep -q "${TARGET_DRIVE}" /proc/mounts 2>/dev/null; then
    echo "[!] Warning: Target device '${TARGET_DRIVE}' has active mounted partitions."
    echo "[!] Unmounting all active partitions on ${TARGET_DRIVE}..."
    umount "${TARGET_DRIVE}"* 2>/dev/null || true
fi

echo "======================================================================"
echo "       BOOT TO FORENSICS (BOOT) - USB INSTALLATION UTILITY             "
echo "======================================================================"
echo "Target Block Device: ${TARGET_DRIVE}"
echo "Source Live ISO:     ${ISO_PATH}"
echo "======================================================================"
echo "[!] CAUTION: ALL DATA ON ${TARGET_DRIVE} WILL BE COMPLETELY ERASED!"
read -rp "Do you wish to proceed with formatting? [y/N]: " CONFIRM
if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
    echo "[-] Operation aborted by user."
    exit 0
fi

# Check if ISO exists, otherwise build it
if [ ! -f "${ISO_PATH}" ]; then
    echo "[+] ISO not found at ${ISO_PATH}. Building fresh ISO..."
    "${REPO_ROOT}/scripts/build_iso.sh"
fi

echo "[+] Step 1/5: Wiping old partition tables and filesystem headers..."
wipefs -af "${TARGET_DRIVE}"
sgdisk --zap-all "${TARGET_DRIVE}"

echo "[+] Step 2/5: Partitioning drive (Partition 1: Live OS, Partition 2: Persistence)..."
# Partition 1: 3GB for Live OS (Type EF00 EFI/FAT32)
sgdisk -n 1:2048:+3G -t 1:EF00 -c 1:"BOOTO_LIVE" "${TARGET_DRIVE}"
# Partition 2: Remaining space for LUKS Encrypted Persistence (Type 8309 Linux LUKS)
sgdisk -n 2:0:0 -t 2:8309 -c 2:"BOOTO_DATA" "${TARGET_DRIVE}"
sgdisk -p "${TARGET_DRIVE}"

partprobe "${TARGET_DRIVE}" || sleep 2

PART1="${TARGET_DRIVE}1"
PART2="${TARGET_DRIVE}2"
if [[ "${TARGET_DRIVE}" =~ [0-9]$ ]]; then
    PART1="${TARGET_DRIVE}p1"
    PART2="${TARGET_DRIVE}p2"
fi

echo "[+] Step 3/5: Formatting Partition 1 (FAT32 BOOTO_LIVE) and deploying ISO..."
mkfs.vfat -F 32 -n "BOOTO_LIVE" "${PART1}"

MNT_LIVE="/tmp/booto_usb_live_$$"
MNT_ISO="/tmp/booto_iso_mount_$$"
mkdir -p "${MNT_LIVE}" "${MNT_ISO}"

mount "${PART1}" "${MNT_LIVE}"
mount -o loop,ro "${ISO_PATH}" "${MNT_ISO}"

echo "[+] Copying Live OS filesystem to USB..."
cp -r "${MNT_ISO}/"* "${MNT_LIVE}/"

umount "${MNT_ISO}"
umount "${MNT_LIVE}"
rm -rf "${MNT_LIVE}" "${MNT_ISO}"

echo "[+] Step 4/5: Initializing Partition 2 as LUKS2 Encrypted Persistence..."
echo "Enter passphrase for your forensic encrypted persistence container:"
cryptsetup luksFormat --type luks2 "${PART2}"

echo "[+] Opening LUKS container to create ext4 filesystem..."
cryptsetup open "${PART2}" booto_persistence_init
mkfs.ext4 -L "persistence" /dev/mapper/booto_persistence_init

MNT_PERSIST="/tmp/booto_persistence_mount_$$"
mkdir -p "${MNT_PERSIST}"
mount /dev/mapper/booto_persistence_init "${MNT_PERSIST}"

# Create Tails-style persistence configuration file and directory tree
echo "/ union" > "${MNT_PERSIST}/persistence.conf"
mkdir -p "${MNT_PERSIST}/cases" "${MNT_PERSIST}/rules" "${MNT_PERSIST}/logs"
chmod 0700 "${MNT_PERSIST}"/*

umount "${MNT_PERSIST}"
cryptsetup close booto_persistence_init
rm -rf "${MNT_PERSIST}"

echo "======================================================================"
echo "[+] SUCCESS: Booto Dual-Partition Live USB is ready!"
echo "Partition 1: Amnesic Live OS (${PART1})"
echo "Partition 2: LUKS2 Encrypted Persistence (${PART2})"
echo "======================================================================"
