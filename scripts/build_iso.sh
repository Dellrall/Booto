#!/usr/bin/env bash
# ==============================================================================
# Booto Debian-Based Live ISO Generator
# Creates a standalone, bootable hybrid ISO (BIOS + UEFI) with Amnesic Live Boot.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WORK_DIR="/tmp/booto_iso_workspace"
ROOTFS_DIR="${WORK_DIR}/chroot"
CD_DIR="${WORK_DIR}/iso_root"
OUTPUT_DIR="${REPO_ROOT}/dist"
ISO_NAME="booto-live-amd64.iso"
DEBIAN_VERSION="bookworm"
DEBIAN_MIRROR="http://deb.debian.org/debian"

echo "=== Booto Live ISO Build Automation ==="
echo "Debian Base: ${DEBIAN_VERSION}"
echo "Output ISO:  ${OUTPUT_DIR}/${ISO_NAME}"

# Ensure root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: ISO generation requires root privileges (sudo)."
    exit 1
fi

# Clean previous build artifacts
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${CD_DIR}/live" "${CD_DIR}/boot/grub" "${OUTPUT_DIR}"

echo "[+] Step 1/6: Compiling latest Booto C11 binary..."
make -C "${REPO_ROOT}" clean all

echo "[+] Step 2/6: Bootstrapping Debian 12 (Bookworm) minimal rootfs..."
debootstrap --arch=amd64 \
            --variant=minbase \
            --include=linux-image-amd64,live-boot,systemd,systemd-sysv,libncurses6,libblkid1,libudev1,cryptsetup,util-linux \
            "${DEBIAN_VERSION}" "${ROOTFS_DIR}" "${DEBIAN_MIRROR}"

echo "[+] Step 3/6: Installing Booto binary into rootfs..."
install -m 755 "${REPO_ROOT}/bin/booto" "${ROOTFS_DIR}/usr/local/bin/booto"

# Configure Hostname and Network
echo "booto-live" > "${ROOTFS_DIR}/etc/hostname"
cat << 'SYSCONFIG' > "${ROOTFS_DIR}/etc/hosts"
127.0.0.1   localhost
127.0.1.1   booto-live
SYSCONFIG

# Configure Autologin on TTY1 to directly launch Booto TUI
mkdir -p "${ROOTFS_DIR}/etc/systemd/system/getty@tty1.service.d"
cat << 'SYSCONFIG' > "${ROOTFS_DIR}/etc/systemd/system/getty@tty1.service.d/override.conf"
[Service]
ExecStart=
ExecStart=-/usr/local/bin/booto
StandardInput=tty
StandardOutput=tty
StandardError=journal
Restart=always
RestartSec=1
SYSCONFIG

echo "[+] Step 4/6: Extracting kernel & initramfs for ISO boot..."
vmlinuz_path=$(ls "${ROOTFS_DIR}/boot"/vmlinuz* | head -n 1)
initrd_path=$(ls "${ROOTFS_DIR}/boot"/initrd.img* | head -n 1)
cp "${vmlinuz_path}" "${CD_DIR}/live/vmlinuz"
cp "${initrd_path}" "${CD_DIR}/live/initrd.img"

echo "[+] Step 5/6: Compressing root filesystem into SquashFS..."
mksquashfs "${ROOTFS_DIR}" "${CD_DIR}/live/filesystem.squashfs" \
           -comp xz -Xbcj x86 -noappend -wildcards

echo "[+] Step 6/6: Assembling GRUB2 hybrid boot configuration..."
cat << 'EOF_GRUB' > "${CD_DIR}/boot/grub/grub.cfg"
set default=0
set timeout=5

insmod font
if loadfont "${prefix}/fonts/unicode.pf2" ; then
    insmod gfxterm
    set gfxmode=auto
    terminal_output gfxterm
fi

menuentry "Booto - Live Rootkit & Bootkit Forensic System (Amnesic RAM Mode)" {
    linux  /live/vmlinuz boot=live components quiet splash systemd.show_status=0 loglevel=3
    initrd /live/initrd.img
}

menuentry "Booto - Live Rootkit & Bootkit Forensic System (Debug Verbose)" {
    linux  /live/vmlinuz boot=live components verbose
    initrd /live/initrd.img
}
EOF_GRUB

# Create EFI Boot Image
mkdir -p "${CD_DIR}/EFI/BOOT"
grub-mkstandalone \
    --format=x86_64-efi \
    --output="${CD_DIR}/EFI/BOOT/BOOTX64.EFI" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=${CD_DIR}/boot/grub/grub.cfg"

# Create standalone hybrid ISO image
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "BOOTO_LIVE" \
    -output "${OUTPUT_DIR}/${ISO_NAME}" \
    -e EFI/BOOT/BOOTX64.EFI \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    "${CD_DIR}"

# Generate SHA-256 Checksum Seal
cd "${OUTPUT_DIR}"
sha256sum "${ISO_NAME}" > "${ISO_NAME}.sha256"

echo "=== ISO Build Complete ==="
echo "Image:    ${OUTPUT_DIR}/${ISO_NAME}"
echo "Checksum: $(cat "${ISO_NAME}.sha256")"
