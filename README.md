# Booto

[![CI](https://github.com/Dellrall/Booto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dellrall/Booto/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/Dellrall/Booto?label=version)](CHANGELOG.md)
[![Standard](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Booto** is an amnesic, Tails-inspired Live Linux forensic framework designed for **out-of-band offline rootkit and bootkit detection**. 

Built with **C11**, Booto runs from a trusted Debian Live USB environment so the suspect system's kernel and userland are never executed while their storage is analysed read-only.

---

## Key Features

- **Amnesic Live OS (Debian 12 Base)**: Runs 100% in RAM (`SquashFS` + `OverlayFS`) with zero host disk tampering.
- **Optional Encrypted Persistence (LUKS2)**: Tails-style secondary encrypted partition (`BOOTO_DATA`) to securely preserve forensic logs, case reports, and custom detection rules.
- **Dual-Partition USB Setup Utility (`scripts/setup_usb.sh`)**: One-command installer creating the Amnesic Live bootloader partition and LUKS2 persistence volume.
- **Zellij-Inspired Movable TUI**: Raw termios/ANSI terminal interface (no ncurses) with a Binary Space Partitioning (BSP) window manager supporting movable, resizable, and zoomable panes.
- **Safe Forensic Storage Discovery & Mounter**: Automatic enumeration of NVMe/SATA/USB block devices via `/proc/partitions` and `sysfs`, enforcing strict read-only mounts (`MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` with `noload`).
- **Low-Level Forensic Detection Modules**:
  - **MBR & VBR Boot Sector Auditor**: Raw sector-level parser for the Master Boot Record (sector 0), the track-0 gap, and partition Volume Boot Records, matched against MBR byte-pattern signatures.
  - **UEFI & ESP Bootkit Analyzer**: PE32+ (PE/COFF) parser that computes each EFI binary's Authenticode hash and matches it against the Secure Boot DBX revocation rules. If the root filesystem's `/boot/efi` is empty, the EFI System Partition is found in the disk's GPT (or MBR type `0xEF`) and mounted read-only for the scan.
  - **Kernel Image & LKM Hook Scanner**: 64-bit ELF parser and symbol-table audit against LKM rootkit signature rules.
  - **Initramfs Auditor**: Decompresses gzip/xz/zstd/lz4/bzip2 initramfs images (and compressed `.ko` modules) via the system tools, parses the CPIO archive, and audits early-boot scripts.
  - **Userland Preload Scanner**: Checks `/etc/ld.so.preload` and `LD_PRELOAD` in `/etc/environment`. PAM modules are not scanned.
  - **Ext4 Superblock Engine**: Reads raw ext4 superblock statistics. It does not perform hidden-inode cross-view analysis.
- **Verdicts**: Every scan ends as `CLEAN`, `THREATS`, or `INCOMPLETE`, with a per-module status; an engine that errors makes the scan `INCOMPLETE` instead of silently passing.
- **Sealed Detection Rules**: Signatures live in `rules/*.json`, each with a SHA-256 seal (`*.json.sha256`); a file whose seal does not match is refused.
- **Defensive Fuzzing, ASan & Multi-Compiler CI**: Deterministic 1,500-iteration-per-parser mutation fuzzing of the ELF, PE, MBR/VBR/gap and initramfs parsers, AddressSanitizer/UBSan builds, and a GCC/Clang matrix.
- **Case Reporting**: Export of machine-readable JSON and human-readable Markdown reports, each with a SHA-256 side file. The side file is an integrity checksum, not a cryptographic signature.
- **Automated ISO Generation (`make iso`)**: Standalone live bootable ISO output ready for USB deployment.

---

## Quick Start & Build Instructions

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

# Generate gcov Code Coverage Report
make coverage

# Launch Interactive Zellij-Style Movable TUI
./bin/booto

# Regenerate the sealed rule files locally (no network fetch)
./bin/booto --update-rules

# Build Debian Live ISO
sudo make iso

# Install to USB Flash Drive (Dual Partition)
sudo ./scripts/setup_usb.sh /dev/sdb
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
| `-u`, `--update-rules` | Regenerate sealed rule files (`scripts/update_rules.sh`) |
| `-V`, `--verbose` | Verbose/debug logging |
| `-v`, `--version` / `-h`, `--help` | Version / help |

Exit codes: `0` CLEAN (every enabled engine ran, nothing found), `1` THREATS, `2` INCOMPLETE (an engine failed, nothing ran, or the scan could not start). Mounting a target needs root; non-root runs cannot mount and report INCOMPLETE.

### Detection Rules

Rule files are searched in order: `$BOOTO_RULES_DIR`, `/persistence/rules`, `/usr/share/booto/rules`, `./rules` (set `BOOTO_RULES_DIR_ONLY=1` to use only `$BOOTO_RULES_DIR`). Each `*.json` must match its `*.json.sha256` seal or it is refused. `--update-rules` runs `scripts/update_rules.sh`, which regenerates and reseals the files; it does not download anything.

The shipped DBX, LKM and MBR signatures are illustrative samples, not an authoritative threat feed. DBX entries are placeholders until real Authenticode revocation hashes are imported.

---

## TUI Window Navigation & Shortcuts

| Shortcut | Action | Description |
| :--- | :--- | :--- |
| `Alt + Arrow` | **Spatial Focus** | Move focus to adjacent pane |
| `Tab` | **Cycle Focus** | Cycle focus through active leaf panes |
| `Alt + M` | **Move / Swap** | Swap the focused pane with the next pane |
| `Alt + Z` | **Zoom / Maximize** | Toggle full-screen on focused pane |
| `Alt + H` | **Split Horizontal** | Split focused pane into top & bottom |
| `Alt + V` | **Split Vertical** | Split focused pane into left & right |
| `Alt + [` / `Alt + ]` | **Resize Split** | Adjust split ratio of the active node |
| `Space` | **Toggle Target** | Toggle target disk flag / toggle scanner module |
| `Enter` | **Mount / Unmount** | Mount target storage strictly READ-ONLY |
| `Mouse Click` | **Click to Focus** | Focus pane by clicking inside its border |
| `F3` | **Unlock LUKS** | Unlock an encrypted target partition read-only |
| `F5` | **Start Scan** | Trigger forensic scanning sequence |
| `F6` | **Export Report** | Export JSON & Markdown case reports with SHA-256 checksums |
| `F10` / `q` | **Exit** | Gracefully shutdown TUI and restore terminal |

The TUI draws with line and symbol glyphs that exist in the Linux console's default (CP437) font, using only the 16 standard colours, so it looks the same on a bare VT as in a terminal emulator. On a terminal without those glyphs (for example some serial consoles), start it with `BOOTO_ASCII=1 booto` to draw plain ASCII instead.

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

---

## License

This project is licensed under the MIT License.


