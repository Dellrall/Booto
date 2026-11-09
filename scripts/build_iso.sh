#!/usr/bin/env bash
# ==============================================================================
# Booto Debian-Based Live ISO Generator
# Creates a standalone, bootable hybrid ISO (BIOS + UEFI) with Amnesic Live Boot.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Reproducible timestamps: derive from the last commit when building from git.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date -u +%s)"
fi
export SOURCE_DATE_EPOCH
ISO_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y%m%d%H%M%S)00"
# ISO9660 UUID that xorriso derives from --modification-date; blkid shows it as /dev/disk/by-uuid/<this>.
ISO_UUID="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%d-%H-%M-%S)-00"

WORK_DIR="/tmp/booto_iso_workspace"
ROOTFS_DIR="${WORK_DIR}/chroot"
CD_DIR="${WORK_DIR}/iso_root"
OUTPUT_DIR="${REPO_ROOT}/dist"
ISO_NAME="${1:-booto-live-amd64.iso}"
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
            --include=linux-image-amd64,live-boot,systemd,systemd-sysv,libncurses6,libblkid1,libudev1,libssl3,libsqlite3-0,cryptsetup,util-linux,gzip,xz-utils,zstd,lz4,bzip2,flashrom,gpm,plymouth,plymouth-label,console-setup-linux,vim-tiny,nano,man-db \
            "${DEBIAN_VERSION}" "${ROOTFS_DIR}" "${DEBIAN_MIRROR}"

echo "[+] Step 3/6: Installing Booto binary into rootfs..."
install -m 755 "${REPO_ROOT}/bin/booto" "${ROOTFS_DIR}/usr/local/bin/booto"
install -d -m 755 "${ROOTFS_DIR}/usr/share/booto/rules"
install -m 644 "${REPO_ROOT}"/rules/*.json "${REPO_ROOT}"/rules/*.json.sha256 "${ROOTFS_DIR}/usr/share/booto/rules/"
install -m 644 "${REPO_ROOT}/LICENSE" "${ROOTFS_DIR}/usr/share/booto/LICENSE"
install -D -m 644 "${REPO_ROOT}/man/booto.1" "${ROOTFS_DIR}/usr/share/man/man1/booto.1"
install -D -m 644 "${REPO_ROOT}/man/booto-checks.7" "${ROOTFS_DIR}/usr/share/man/man7/booto-checks.7"
# The dbx rules derive from Microsoft's secureboot_objects (BSD-2-Clause-Patent): ship its notice.
install -m 644 "${REPO_ROOT}/rules/sources/secureboot_objects-License.txt" "${ROOTFS_DIR}/usr/share/booto/rules/"
# The firmware audit reads SMM/SMRR lock bits through /dev/cpu/N/msr (read-only).
install -d -m 755 "${ROOTFS_DIR}/etc/modules-load.d"
echo "msr" > "${ROOTFS_DIR}/etc/modules-load.d/booto.conf"
# gpm passes the mouse to the text console, which forwards it to the TUI as X10 reports
chroot "${ROOTFS_DIR}" systemctl enable gpm.service
# Boot splash between GRUB and the TUI; getty@tty1 waits for plymouth to quit, so Booto starts on a clean screen.
install -d -m 755 "${ROOTFS_DIR}/usr/share/plymouth/themes/booto"
install -m 644 "${REPO_ROOT}"/assets/plymouth/* "${ROOTFS_DIR}/usr/share/plymouth/themes/booto/"
chroot "${ROOTFS_DIR}" plymouth-set-default-theme -R booto

# Configure Hostname and Network
echo "booto-live" > "${ROOTFS_DIR}/etc/hostname"
cat << 'SYSCONFIG' > "${ROOTFS_DIR}/etc/hosts"
127.0.0.1   localhost
127.0.1.1   booto-live
SYSCONFIG

# Configure Autologin on TTY1 to directly launch Booto TUI and drop to bash on exit
mkdir -p "${ROOTFS_DIR}/etc/systemd/system/getty@tty1.service.d"
cat << 'SYSCONFIG' > "${ROOTFS_DIR}/etc/systemd/system/getty@tty1.service.d/override.conf"
[Service]
# Terminus: crisper than the VGA font, same 8x16 cell, and has every glyph the TUI draws
ExecStartPre=-/usr/bin/setfont /usr/share/consolefonts/Uni2-Terminus16.psf.gz
ExecStart=
ExecStart=-/bin/bash -c "/usr/local/bin/booto; exec /bin/bash 2>&1"
StandardInput=tty
StandardOutput=tty
StandardError=journal
Restart=no
SYSCONFIG

echo "[+] Step 4/6: Extracting kernel & initramfs for ISO boot..."
vmlinuz_path=$(ls "${ROOTFS_DIR}/boot"/vmlinuz* | head -n 1)
initrd_path=$(ls "${ROOTFS_DIR}/boot"/initrd.img* | head -n 1)
cp "${vmlinuz_path}" "${CD_DIR}/live/vmlinuz"
cp "${initrd_path}" "${CD_DIR}/live/initrd.img"
# GRUB must boot this medium, never a /live tree planted on the suspect disk: search for a
# per-build marker instead of /live/vmlinuz. setup_usb.sh copies it along with the ISO files.
BOOT_ID="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo nogit)-${SOURCE_DATE_EPOCH}"
BOOT_MARKER="/live/booto-${BOOT_ID}.id"
echo "${BOOT_ID}" > "${CD_DIR}${BOOT_MARKER}"

echo "[+] Step 5/6: Compressing root filesystem into SquashFS..."
# mksquashfs reads the exported SOURCE_DATE_EPOCH itself and rejects -mkfs-time/-all-time alongside it.
mksquashfs "${ROOTFS_DIR}" "${CD_DIR}/live/filesystem.squashfs" \
           -comp xz -Xbcj x86 -noappend -wildcards

echo "[+] Step 6/6: Assembling GRUB2 hybrid boot configuration..."
# live-media=removable: live-boot must not take filesystem.squashfs from an internal (suspect) disk.
# systemd.swap=no: never activate swap found on the suspect disk.
cat << EOF_GRUB > "${CD_DIR}/boot/grub/grub.cfg"
set default=0
set timeout=5

insmod part_gpt
insmod part_msdos
insmod fat
insmod iso9660
insmod search
insmod search_fs_file
insmod search_label
insmod linux
insmod font
insmod gfxterm

search --no-floppy --set=root --file ${BOOT_MARKER}

menuentry "Booto - Live Rootkit & Bootkit Forensic System (Amnesic RAM Mode)" {
    search --no-floppy --set=root --file ${BOOT_MARKER}
    linux  /live/vmlinuz boot=live components live-media=removable systemd.swap=no iomem=relaxed quiet splash systemd.show_status=0 loglevel=3
    initrd /live/initrd.img
}

# Fallback for USB SSDs/enclosures that do not report removable: find this build's ISO by UUID (same trust as the GRUB search above).
menuentry "Booto - USB not detected (non-removable USB drive)" {
    search --no-floppy --set=root --file ${BOOT_MARKER}
    linux  /live/vmlinuz boot=live components live-media=/dev/disk/by-uuid/${ISO_UUID} systemd.swap=no iomem=relaxed quiet splash systemd.show_status=0 loglevel=3
    initrd /live/initrd.img
}

menuentry "Booto - Live Rootkit & Bootkit Forensic System (Debug Verbose)" {
    search --no-floppy --set=root --file ${BOOT_MARKER}
    linux  /live/vmlinuz boot=live components live-media=removable systemd.swap=no iomem=relaxed verbose
    initrd /live/initrd.img
}
EOF_GRUB

# Create EFI Bootloader and FAT efiboot.img
mkdir -p "${CD_DIR}/EFI/BOOT" "${CD_DIR}/boot/grub"
grub-mkstandalone \
    --format=x86_64-efi \
    --output="${CD_DIR}/EFI/BOOT/BOOTX64.EFI" \
    --install-modules="part_gpt part_msdos fat iso9660 search search_fs_file search_label linux normal font gfxterm all_video" \
    --modules="part_gpt part_msdos fat iso9660 search search_fs_file search_label linux normal font gfxterm all_video" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=${CD_DIR}/boot/grub/grub.cfg"

# Create proper FAT filesystem image containing the EFI bootloader
dd if=/dev/zero of="${WORK_DIR}/efiboot.img" bs=1M count=16
mkfs.vfat -F 12 -n "BOOT_EFI" "${WORK_DIR}/efiboot.img"
mmd -i "${WORK_DIR}/efiboot.img" ::/EFI ::/EFI/BOOT
mcopy -i "${WORK_DIR}/efiboot.img" "${CD_DIR}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
cp "${WORK_DIR}/efiboot.img" "${CD_DIR}/boot/grub/efiboot.img"

# Create BIOS GRUB bootloader if i386-pc is available
BIOS_FLAG=""
if [ -f /usr/lib/grub/i386-pc/cdboot.img ]; then
    echo "[+] Generating Legacy BIOS boot image (i386-pc)..."
    grub-mkstandalone \
        --format=i386-pc \
        --output="${WORK_DIR}/core.img" \
        --install-modules="part_gpt part_msdos fat iso9660 biosdisk search search_fs_file search_label linux normal configfile" \
        --modules="part_gpt part_msdos fat iso9660 biosdisk search search_fs_file search_label linux normal configfile" \
        --locales="" \
        --fonts="" \
        "boot/grub/grub.cfg=${CD_DIR}/boot/grub/grub.cfg"
    cat /usr/lib/grub/i386-pc/cdboot.img "${WORK_DIR}/core.img" > "${CD_DIR}/boot/grub/bios.img"
fi

# Create standalone hybrid ISO image (Universal Dual BIOS + UEFI)
if [ -f "${CD_DIR}/boot/grub/bios.img" ]; then
    echo "[+] Building Dual BIOS + UEFI Hybrid ISO..."
    # --grub2-mbr: MBR boot code so BIOS can boot the ISO raw-written to a USB disk (El Torito alone only boots as CD).
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "BOOTO_LIVE" \
        --modification-date="${ISO_DATE}" \
        -output "${OUTPUT_DIR}/${ISO_NAME}" \
        --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img --grub2-boot-info \
        -b boot/grub/bios.img \
        -c boot.catalog \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        --eltorito-alt-boot \
        -e boot/grub/efiboot.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        "${CD_DIR}"
else
    echo "[+] Building UEFI Hybrid ISO with FAT efiboot..."
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "BOOTO_LIVE" \
        --modification-date="${ISO_DATE}" \
        -output "${OUTPUT_DIR}/${ISO_NAME}" \
        -e boot/grub/efiboot.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        "${CD_DIR}"
fi

# Generate SHA-256 Checksum Seal
cd "${OUTPUT_DIR}"
sha256sum "${ISO_NAME}" > "${ISO_NAME}.sha256"

echo "=== ISO Build Complete ==="
echo "Image:    ${OUTPUT_DIR}/${ISO_NAME}"
echo "Checksum: $(cat "${ISO_NAME}.sha256")"
