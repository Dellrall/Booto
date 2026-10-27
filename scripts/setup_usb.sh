#!/usr/bin/env bash
# ==============================================================================
# Booto Dual-Partition Tails-Style USB Installer Utility
# Formats USB drive into Live OS (Partition 1) and Encrypted Persistence (Partition 2).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    echo "Usage: sudo $0 [--yes] [--force-nonremovable] <target_disk e.g. /dev/sdb> [iso_path]"
    exit 1
}

ASSUME_YES=0
FORCE_NONREMOVABLE=0
POSITIONAL=()
for arg in "$@"; do
    case "${arg}" in
        --yes) ASSUME_YES=1 ;;
        --force-nonremovable) FORCE_NONREMOVABLE=1 ;;
        -h|--help) usage ;;
        -*) echo "[-] Error: unknown option '${arg}'" >&2; usage ;;
        *) POSITIONAL+=("${arg}") ;;
    esac
done

TARGET_DRIVE="${POSITIONAL[0]:-}"
ISO_PATH="${POSITIONAL[1]:-${REPO_ROOT}/dist/booto-live-amd64.iso}"
[ -n "${TARGET_DRIVE}" ] || usage

die() { echo "[-] Error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "USB setup utility requires root privileges (sudo)."

for tool in lsblk findmnt wipefs sgdisk partprobe udevadm mkfs.vfat mkfs.ext4 cryptsetup; do
    command -v "${tool}" >/dev/null || die "required tool '${tool}' not found in PATH."
done

[ -b "${TARGET_DRIVE}" ] || die "'${TARGET_DRIVE}' is not a block device."
[ "$(lsblk -dno TYPE "${TARGET_DRIVE}")" = "disk" ] || die "'${TARGET_DRIVE}' is not a whole disk (pass e.g. /dev/sdb, not /dev/sdb1)."

# Refuse any disk that backs the running system (covers LVM/LUKS/RAID children via lsblk's tree).
for mp in / /boot /boot/efi; do
    src="$(findmnt -nvro SOURCE --target "${mp}" 2>/dev/null || true)"
    [ -n "${src}" ] && [ -b "${src}" ] || continue
    for parent in $(lsblk -nso NAME,TYPE "${src}" | awk '$2 == "disk" { print $1 }'); do
        [ "/dev/${parent}" -ef "${TARGET_DRIVE}" ] && die "'${TARGET_DRIVE}' backs ${mp}; refusing to wipe the running system disk."
    done
done

if [ "$(lsblk -dno RM "${TARGET_DRIVE}" | tr -d ' ')" != "1" ] && [ "${FORCE_NONREMOVABLE}" -ne 1 ]; then
    die "'${TARGET_DRIVE}' is not a removable disk; pass --force-nonremovable if you are sure."
fi

echo "======================================================================"
echo "       BOOT TO FORENSICS (BOOT) - USB INSTALLATION UTILITY             "
echo "======================================================================"
echo "Target Block Device: ${TARGET_DRIVE}"
echo "Model / Size / Serial: $(lsblk -dno MODEL,SIZE,SERIAL "${TARGET_DRIVE}")"
echo "Source Live ISO:     ${ISO_PATH}"
echo "Current layout:"
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT "${TARGET_DRIVE}"
echo "======================================================================"
echo "[!] CAUTION: ALL DATA ON ${TARGET_DRIVE} WILL BE COMPLETELY ERASED!"
if [ "${ASSUME_YES}" -ne 1 ]; then
    read -rp "Type the device path (${TARGET_DRIVE}) to confirm: " CONFIRM
    if [ "${CONFIRM}" != "${TARGET_DRIVE}" ]; then
        echo "[-] Confirmation did not match; operation aborted."
        exit 1
    fi
fi

# Unmount each mounted child individually; abort if any refuses.
while read -r name mnt; do
    [ -n "${mnt}" ] || continue
    echo "[+] Unmounting /dev/${name} from ${mnt}..."
    umount "/dev/${name}" || die "failed to unmount /dev/${name} (${mnt}); aborting."
done < <(lsblk -nro NAME,MOUNTPOINT "${TARGET_DRIVE}")
if lsblk -nro MOUNTPOINT "${TARGET_DRIVE}" | grep -q .; then
    die "'${TARGET_DRIVE}' still has mounted filesystems; aborting."
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

partprobe "${TARGET_DRIVE}"
udevadm settle

PART1="${TARGET_DRIVE}1"
PART2="${TARGET_DRIVE}2"
if [[ "${TARGET_DRIVE}" =~ [0-9]$ ]]; then
    PART1="${TARGET_DRIVE}p1"
    PART2="${TARGET_DRIVE}p2"
fi
for part in "${PART1}" "${PART2}"; do
    [ -b "${part}" ] || die "partition node ${part} did not appear after partitioning."
done

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
