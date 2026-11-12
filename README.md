# Booto

[![CI](https://github.com/Dellrall/Booto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dellrall/Booto/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/Dellrall/Booto?label=version&include_prereleases)](CHANGELOG.md)
[![Standard](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

**Booto** is an amnesic, Tails-inspired Live Linux forensic framework designed for **out-of-band offline rootkit and bootkit detection**. 

Built with **C11**, Booto runs from a trusted Debian Live USB environment so the suspect system's kernel and userland are never executed while their storage is analysed read-only.

> **Status: beta.** Booto is fine for triage, but has not yet been validated against real bootkit samples or across many clean machines. Do not treat a clean report as proof a system is uncompromised. Releases are tagged `-beta` and published as pre-releases until that changes.

---

## Key Features

- **Amnesic Live OS (Debian 12 Base)**: Runs 100% in RAM (`SquashFS` + `OverlayFS`) with zero host disk tampering. Boots with Secure Boot on (Debian's signed shim, GRUB and kernel) or off, and carries Debian's security updates.
- **Report Storage on the USB (`BOOTO_DATA`)**: reports, logs and custom rules persist on a partition of the stick, LUKS2-encrypted (passphrase asked when the TUI starts) or plain ext4 (mounted without asking). Booto only uses the partition on the stick it booted from.
- **Dual-Partition USB Setup Utility (`scripts/setup_usb.sh`)**: One-command installer creating the Amnesic Live bootloader partition and the report partition, with or without a passphrase. Written raw instead (`dd`, Rufus DD mode, caligula, Etcher)? `F4` in Booto runs `booto-storage create` to add the report partition from inside the live system, like Tails.
- **Zellij-Inspired Movable TUI**: Raw termios/ANSI terminal interface (no ncurses) with a Binary Space Partitioning (BSP) window manager supporting movable, resizable, and zoomable panes.
- **Safe Forensic Storage Discovery & Mounter**: Automatic enumeration of NVMe/SATA/USB block devices via `/proc/partitions` and `sysfs` (ext4, xfs, btrfs, NTFS, LUKS and LVM, including LVM inside LUKS, activated read-only), enforcing strict read-only mounts (`MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` with `noload`).
- **Low-Level Forensic Detection Modules**:
  - **MBR & VBR Boot Sector Auditor**: Raw sector-level parser for the Master Boot Record (sector 0), the track-0 gap, and partition Volume Boot Records, matched against MBR byte-pattern signatures.
  - **UEFI & ESP Bootkit Analyzer**: PE32+ (PE/COFF) parser that finds every PE on the ESP by its `MZ` header (not its name), computes each one's Authenticode hash and matches it against the Secure Boot DBX revocation rules, and verifies the embedded Authenticode signature so a signed loader patched after signing is flagged. A first-stage loader (`boot*`, `shim*`) with a valid signature that does not chain to a Microsoft root is flagged too (`UEFI_FIRST_STAGE_NOT_MICROSOFT`). If the root filesystem's `/boot/efi` is empty, the EFI System Partition is found in the disk's GPT (or MBR type `0xEF`) and mounted read-only for the scan.
  - **Kernel Image & LKM Hook Scanner**: 64-bit ELF parser and symbol-table audit against LKM rootkit signature rules. When the kernel's own modules are signed, a module without a signature block is flagged (`LKM_UNSIGNED`; the marker text alone does not count, and the signature is not verified against the kernel's keys); a self-built kernel that signs nothing is left alone.
  - **Initramfs Auditor**: Decompresses gzip/xz/zstd/lz4/bzip2 initramfs images (and compressed `.ko` modules) via the system tools, parses the CPIO archive, and audits early-boot scripts.
  - **Userland Preload Scanner**: Checks `/etc/ld.so.preload` and `LD_PRELOAD` in `/etc/environment`. PAM modules are not scanned.
  - **Package Integrity Engine**: Re-hashes packaged system binaries and libraries against the target's dpkg `md5sums` lists, pacman `mtree` SHA-256 digests and the RPM `rpmdb.sqlite` file digests (debsums / `pacman -Qkk`-style, offline), flagging files whose content no longer matches the package. Debian-, Arch- and RPM-based roots. It trusts the database on the target disk.
  - **Windows Boot Chain Check**: On a Windows root (NTFS, mounted read-only with `ntfs3`), verifies the embedded Authenticode signatures of `winload`, `winresume`, `ntoskrnl.exe`, `hal.dll`, `ci.dll` and every boot driver in `System32/drivers` against Microsoft's roots, flagging a file patched after signing or signed by someone else (FinSpy/ESPecter-style). Also checks the ESP's `bootmgfw.efi` against the newest boot log Windows saved (`Windows/Logs/MeasuredBoot`) and notes a mismatch outside the verdict. Reads the BCD store (testsigning, nointegritychecks, debuggers, a changed winload path) and checks every boot-start driver the SYSTEM hive lists. A BitLocker volume is detected and reported as encrypted, not scanned (verdict INCOMPLETE); unlocking it is not supported yet.
  - **Host Firmware Audit** (device mode only, not part of the disk verdict): Secure Boot and setup mode, enrolled platform key, PKfail test keys in `PK`/`KEK`/`db`, `dbx` revocation count, shim's MOK list (keys not shipped by a known distro, or bare binary hashes, fail), a pending one-shot `BootNext` override (fails; the first boot entry and its loader path are shown), ACPI DMAR/IVRS IOMMU tables, Thunderbolt DMA protection, silicon locks (SMM lock, SMRR/TSEG, Intel BIOS write protection, CPU debug interface lock), Intel ME operating mode and Boot Guard state, and TPM boot measurements (the firmware's event log is replayed and must reproduce the TPM's PCR 0-7; the PCR0 firmware digest is shown so scans of the same machine can be compared). Read-only; ACPI tables, PCI config space, CPU registers and the TPM event log need root (otherwise reported as `unknown`), and virtual machines report the silicon checks as `unknown`.
    On an older or unrecognised Intel chipset, `booto -c -t <disk>` prints three commands whose output helps confirm the chipset's register layout; paste it in a [GitHub issue](https://github.com/Dellrall/Booto/issues).
- **Write Blocker & Before/After Proof**: At boot a udev rule sets every disk and partition except the Booto USB read-only (`blockdev --setro`). Reports record the SHA-256 of the target's first 1 MiB before mounting and after unmounting, and say `unchanged` or `CHANGED`.
- **Verdicts**: Every scan ends as `CLEAN`, `THREATS`, or `INCOMPLETE`, with a per-module status; an engine that errors makes the scan `INCOMPLETE` instead of silently passing.
- **Signed Detection Rules**: Signatures live in `rules/*.json`, each with an Ed25519 signature (`*.json.sig`) checked against a public key built into the binary; an unsigned or altered file is refused. YARA rules in `rules/bootkits.yar` (signed the same way) are matched against every PE image the UEFI and Windows checks read, every kernel module and every ELF file in the initramfs; a match on a Microsoft-signed image is not reported.
- **Defensive Fuzzing, ASan & Multi-Compiler CI**: Deterministic 1,500-iteration-per-parser mutation fuzzing of the ELF, PE, MBR/VBR/gap and initramfs parsers, AddressSanitizer/UBSan builds, and a GCC/Clang matrix.
- **Case Reporting**: Export of a one-line JSON report and a compact Markdown report (about 1.3 KB together per case), each with a SHA-256 side file (`sha256sum -c` works from the cases directory). The side file is an integrity checksum, not a cryptographic signature.
- **Automated ISO Generation (`make iso`)**: Standalone live bootable ISO output ready for USB deployment.

---

## Quick Start & Build Instructions

Full requirements and step-by-step USB setup, boot and scan instructions: [docs/SETUP.md](docs/SETUP.md).

Each release ISO carries a GitHub build provenance attestation. To check that a downloaded ISO was built by this repository's CI and not altered: `gh attestation verify booto-<version>-amd64.iso --repo Dellrall/Booto`.

### Dependencies (Debian / Ubuntu)
```bash
sudo apt-get install -y build-essential libblkid-dev libudev-dev

# Runtime tools used on the live system (LUKS persistence, initramfs/module decompression)
sudo apt-get install -y cryptsetup gzip xz-utils zstd lz4 bzip2
```

### Build & Run
```bash
# Build the binary (auto-generates version.h)
make all

# Run all unit test & fuzzing suites
make test

# Run with AddressSanitizer & UndefinedBehaviorSanitizer
make asan

# Prove the PE/Authenticode, GPT/MBR and ELF parsers memory-safe on every bounded input (needs cbmc)
make cbmc

# Generate gcov Code Coverage Report
make coverage

# Launch Interactive Zellij-Style Movable TUI
./bin/booto

# Regenerate the rule files locally (no network fetch)
./bin/booto --update-rules

# Build Debian Live ISO
sudo make iso

# Install to USB Flash Drive (Dual Partition)
sudo ./scripts/setup_usb.sh /dev/sdb
# Cap the reports/persistence partition (default: rest of the drive); --no-encrypt skips the passphrase:
sudo ./scripts/setup_usb.sh --data-size=512M --no-encrypt /dev/sdb
# Or write the ISO raw with any tool and press F4 in Booto to create the report partition:
sudo dd if=dist/booto-live-amd64.iso of=/dev/sdb bs=4M conv=fsync status=progress
# The live system loads only from removable media (USB stick, CD/DVD); a USB SSD that
# reports itself as non-removable needs the "USB not detected" GRUB entry, which finds this
# build's ISO by UUID. The default keeps a /live tree planted on the suspect disk from
# replacing the forensic system.
```

---

## Headless CLI

```bash
sudo ./bin/booto -c -t /dev/sdb2 -p /persistence/cases   # scan a block device, write reports
sudo ./bin/booto -c -s /mnt/evidence                      # scan an already-mounted rootfs
./bin/booto -c -t /dev/sdb2 -d                            # dry run: print the plan, touch nothing
```

| Flag | Description |
| :--- | :--- |
| `-c`, `--cli` | Run headless (default is the TUI) |
| `-t`, `--target <dev>` | Raw block device to scan (mounted read-only) |
| `-s`, `--scan-dir <path>` | Local rootfs path to inspect |
| `-p`, `--persistence-dir <dir>` | Write JSON + Markdown case reports to `<dir>` |
| `-d`, `--dry-run` | Print the planned scan and exit without touching any disk |
| `-m`, `--mock-drives` | Inject virtual mock drives for TUI testing |
| `-u`, `--update-rules` | Regenerate rule files (`scripts/update_rules.sh`) |
| `-V`, `--verbose` | Verbose/debug logging |
| `-x`, `--expert-firmware` | Off by default. After a CLI scan, as root: check for a hidden hypervisor under Booto (CPUID slow but no hypervisor announced), flag UEFI variables that hide a PE/ELF image or a large packed blob, and dump the SPI flash read-only with `flashrom` (saved as `spi_flash.bin` in `-p <dir>`, else `/tmp`, with its SHA-256), then walk the image: LZMA sections are inflated by the sandboxed `xz` and a Windows executable hidden in the firmware is flagged. Slower; reported like the host firmware audit, never part of the verdict |
| `-q`, `--quarantine` | Off by default; CLI with `-p <dir>`. Copies every flagged file (kernel module, EFI binary, initrd image, preloaded library, modified package file; first 1 MiB of the raw device for MBR findings) into `<dir>/quarantine/booto-quarantine-<time>.zip`: stored entries, ZipCrypto, password `infected`, names ending in `.malware`, mode 0400. Nothing in it can run when the USB is plugged in elsewhere; unpack only on an isolated analysis machine. The report partition is also mounted `noexec` |
| `--baseline <file>` | CLI. Also writes the SHA-256 of the boot chain to `<file>`: first 1 MiB of the device, every file under `/boot`, an auto-found ESP, Windows core boot files. Run it once on a machine you trust |
| `--bodyfile <file>` | CLI. Writes a Sleuth Kit bodyfile (inode, mode, owner, size and the access, modify and change times) of every file on the scanned root, for a timeline with `mactime -b <file> -d` |
| `--compare <file>` | CLI. Lists each boot chain file that changed, went missing or is new since that baseline. Catches tampering no signature knows; an OS update explains most changes. Does not change the verdict |
| `-v`, `--version` / `-h`, `--help` | Version / help |

Exit codes: `0` CLEAN (every enabled engine ran, nothing found), `1` THREATS, `2` INCOMPLETE (an engine failed, nothing ran, or the scan could not start). Mounting a target needs root; non-root runs cannot mount and report INCOMPLETE.

### Detection Rules

Rule files are searched in order: `$BOOTO_RULES_DIR`, `/persistence/rules`, `/usr/share/booto/rules`, `./rules` (set `BOOTO_RULES_DIR_ONLY=1` to use only `$BOOTO_RULES_DIR`). Each `*.json` needs a valid `*.json.sig` (Ed25519, over the file's exact bytes) or it is refused, so an attacker who can edit the rules cannot re-sign them. `--update-rules` runs `scripts/update_rules.sh`, which regenerates the files and, when `BOOTO_RULES_SIGNING_KEY=<private key PEM>` is set, signs them; it does not download anything.

**Offline rule update:** copy a newer signed pack (each `*.json` and `bootkits.yar` with its `.sig`, from a newer release's `rules/`) into `rules/` on the `BOOTO_DATA` partition, which the live system mounts at `/persistence/rules`. Booto picks it up at the next start, ahead of the rules on the ISO. A file there that is unsigned or altered is refused and its engine reports an error rather than falling back to the ISO's copy, so a bad pack cannot quietly weaken a scan.

The DBX rules come from Microsoft's dbx list. The shipped LKM, MBR and IOC signatures are illustrative samples, not an authoritative threat feed.

---

On the live system, `man booto` lists every option, key and error, and `man booto-checks` explains each finding ID. Read them from the repo with `man -l man/booto.1`.

### Measured Detection

`make zoo` builds a small test zoo and scans every case with `booto -c`; CI runs it on each push. A planted case is a clean install plus one harmless look-alike of a threat, and passes only when the expected engine fires and no other does. A clean case passes only when nothing fires.

| Set | Cases | Result |
|---|---|---|
| Planted | Rovnix MBR hook bytes, ESP loader patched after signing, self-signed first-stage ESP loader, unsigned module beside signed ones, module with a faked signature marker, reverse shell in the initramfs, `ld.so.preload` hook, changed packaged binary, patched `winload.efi` | 9 of 9 caught |
| Clean | minimal Debian (dpkg), Arch (pacman) and Fedora (rpm) installs | 0 of 3 false alarms |

These numbers cover synthetic look-alikes only: one or two cases per engine, no real malware samples and no real distro images. There is no clean Windows case yet, because that needs a Microsoft-signed `ntoskrnl.exe`, which the zoo cannot generate.

## TUI Window Navigation & Shortcuts

| Shortcut | Action | Description |
| :--- | :--- | :--- |
| `Alt + Arrow` | **Spatial Focus** | Move focus to adjacent pane |
| `E` | **Expert View** | Switch between the simple view (Storage and Threat inspector) and the full dashboard with the Engines and Log panes |
| `Tab` | **Cycle Focus** | Cycle focus through active leaf panes |
| `Alt + M` | **Move / Swap** | Swap the focused pane with the next pane |
| `Alt + Z` | **Zoom / Maximize** | Toggle full-screen on focused pane |
| `Alt + H` | **Split Horizontal** | Split focused pane into top & bottom |
| `Alt + V` | **Split Vertical** | Split focused pane into left & right |
| `Alt + [` / `Alt + ]` | **Resize Split** | Adjust split ratio of the active node |
| `Space` | **Select Target** | Select the drive to scan (one at a time; Booto preselects the likeliest installed system) / toggle scanner module |
| `Enter` | **Mount / Unmount** | Mount target storage strictly READ-ONLY |
| `Mouse Click` | **Click to Focus** | Focus a pane and select the row under the pointer; clicking a row's checkbox toggles it |
| `Double-Click` | **Activate** | Mount or unlock the drive, or switch the engine on or off |
| `Right-Click` | **Menu** | The pane's actions plus zoom, split, swap and resize; each row shows its key |
| `Mouse Drag` | **Resize** | Drag a pane border (or the cell beside it); the pointer turns into `↔`/`↕` over one |
| `Mouse Wheel` | **Scroll** | Scroll the pane under the pointer; `↑`/`↓` or `j`/`k` scroll the focused Findings and Reports panes |
| `1`-`4` / `Esc` | **Pages** | Panes, Findings (every finding with its rule, hash and detail), Firmware, Evidence (before/after hash, quarantine, what each engine read); click a tab too; `Esc` back to the panes |
| `?` | **Help** | What each key does |
| `f` | **Filter** | Findings page: show MEDIUM and above, HIGH and above, or all |
| `F3` | **Unlock LUKS** | Unlock an encrypted target partition read-only |
| `F4` | **Unlock Storage** | Mount the report partition on the boot USB (asks for its passphrase if encrypted); on a USB without one, create it in the free space |
| `F5` | **Start Scan** | Trigger forensic scanning sequence |
| `F6` | **Export Report** | Export JSON & Markdown case reports with SHA-256 checksums |
| `F7` | **Quarantine** | Toggle export of flagged files to an encrypted ZIP (password `infected`) on report storage |
| `F10` / `q` | **Exit** | Gracefully shutdown TUI and restore terminal |

The TUI draws with line and symbol glyphs that exist in the Linux console's default (CP437) font, using only the 16 standard colours, so it looks the same on a bare VT as in a terminal emulator. On a terminal without those glyphs (for example some serial consoles), start it with `BOOTO_ASCII=1 booto` to draw plain ASCII instead.

Set `NO_COLOR=1` (see [no-color.org](https://no-color.org)) for a monochrome TUI: bold, dim and reverse video still mark focus, the cursor row and key labels, and every severity is also written out in words. Log and banner colors are also dropped when output is not a terminal.

---

## Development Milestones

| Stage | Version | Description | Status |
| :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.1.0-alpha` | Project Foundation, Toolchain, Dynamic Versioning & CI/CD | **Completed** |
| **Stage 2** | `v0.1.5-alpha` | Zellij-Style Movable TUI Window Manager (raw termios/ANSI BSP Tree) | **Completed** |
| **Stage 3** | `v0.2.0-alpha` | Target Storage Discovery (`libblkid`) & Safe RO Mounter | **Completed** |
| **Stage 4** | `v0.4.0-beta`  | Modular Detection Engines (MBR, UEFI, LKM, Initrd, Preload, Ext4 stats) | **Completed** |
| **Stage 5** | `v0.5.0-rc1`   | Tails-Style LUKS2 Persistence & Case Reporting | **Completed** |
| **Stage 6** | `v0.6.0-rc1`   | Dedicated Testing & Fuzzing Harness (Synthetic Disks, ASan) | **Completed** |
| **Stage 7** | `v0.7.0-rc1`   | Advanced CI/CD Matrix, Sanitizers & Code Coverage | **Completed** |
| **Stage 8** | `v0.8.0-rc1`   | Debian Live ISO Packaging (`make iso`) & Automated CD | **Completed** |
| **Stage 9** | `v1.0.0`       | QEMU Testbed & Capstone Defense Evaluation | **Completed** |
| **Stage 10** | `v1.1.0` | MBR, Track-0 Gap & VBR Bootkit Engine | **Completed** |
| **Stage 11** | `v1.2.0` | Host Firmware Audit, ESP Auto-Discovery, Headless CLI, Runtime Rules Loader | **Completed** |
| **Stage 12** | `v1.3.0` | Firmware Audit: Silicon Locks (SMM, BIOS Write Protection) | **Completed** |
| **Stage 13** | `v1.4.0` | TPM Boot Measurements, Bounded Model Checking, Microsoft dbx Rules | **Completed** |
| **Stage 14** | `v1.5.0-beta` | Quarantine Export, Mouse & Scrolling in the TUI | **Completed** |
| **Stage 15** | `v1.6.0-beta` | Expert Firmware Scan (SPI Dump), Inspect View, Resizable Panes | **Completed** |
| **Stage 16** | `v1.7.0-beta` | Live Console Mouse, Man Pages | **Completed** |
| **Stage 17** | `v1.8.0-beta` | Right-Click Menu, Double-Click, Hover Highlight | **Completed** |
| **Stage 18** | `v1.9.0-beta` | Windows Boot Chain, Baselines, Signed Rules, YARA, Detection Zoo | **Completed** |
| **Stage 18.x** | `v1.9.8-beta` | Write Blocker, Before/After Proof, YARA for Linux, TUI Pages, Secure Boot, In-OS Report Storage, Crash Reports, Beginner View, Hidden Hypervisor Probe | **Completed** |
| **Stage 19** | `v1.10.0-beta` | YARA on ELF Binaries, FwHunt UEFI Rules, Shim Vendor Signing, Bodyfile Timeline, ME / Boot Guard / Debug Lock Checks | **Completed** |

Releases tagged `-beta` are pre-releases: Booto has not yet been validated against real bootkits on real hardware.

---

## License

Copyright (c) 2026 Lye Wei Lun and Booto contributors. Booto is free software under the GNU General Public License, version 3 or (at your option) any later version; see [LICENSE](LICENSE). Releases up to and including 1.6.0-beta were published under MIT.

The UEFI dbx rules (`rules/uefi_dbx_revocations.json`, `src/dbx_builtin.inc`) are generated from Microsoft's [secureboot_objects](https://github.com/microsoft/secureboot_objects) dbx list, © Microsoft Corporation, BSD-2-Clause-Patent; see `rules/sources/secureboot_objects-License.txt`. To update them, replace `rules/sources/dbx_info_msft_latest.json` with the latest `PreSignedObjects/DBX/dbx_info_msft_latest.json` and run `scripts/update_rules.sh rules`. The weekly `Upstream Rules Check` workflow does this and opens an unsigned PR when Microsoft changes the list; re-sign it before merging.


