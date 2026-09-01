# Booto

[![CI](https://github.com/Dellrall/Booto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dellrall/Booto/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.4.0--beta-blue.svg)](CHANGELOG.md)
[![Standard](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Booto** is an amnesic, Tails-inspired Live Linux forensic framework designed for **out-of-band offline rootkit and bootkit detection**. 

Built with low-level **C11**, Booto operates from a trusted Debian Live USB environment, bypassing all runtime kernel-space (Ring-0) and userland evasion techniques to conduct strict read-only forensic analysis of host storage devices.

---

## Key Features

- **Amnesic Live OS (Debian 12 Base)**: Runs 100% in RAM (`SquashFS` + `OverlayFS`) with zero host disk tampering.
- **Optional Encrypted Persistence (LUKS2)**: Tails-style secondary encrypted partition to securely preserve forensic logs, case reports, and custom detection rules.
- **Zellij-Inspired Movable TUI**: Terminal User Interface with a dynamic Binary Space Partitioning (BSP) window manager supporting movable, resizable, and zoomable workspace panes.
- **Safe Forensic Storage Discovery & Mounter**: Automatic enumeration of NVMe/SATA/USB block devices via `/proc/partitions` and `sysfs`, enforcing strict read-only mounts (`MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` with `noload`).
- **Low-Level Forensic Detection Modules**:
  - **Kernel Image & LKM Hook Scanner**: Custom 64-bit ELF parser, symbol table auditing, `sys_call_table` tampering detection, DKOM process/module hiding rules (Diamorphine, Reptile, Suterusu, Khook).
  - **UEFI & ESP Bootkit Analyzer**: PE32+ (PE/COFF) binary parser, Authenticode certificate validator, Secure Boot DBX revocation list matcher (BlackLotus, BootHole, ESPecter, MoonBounce).
  - **In-Memory Initramfs Decompressor**: CPIO archive parser and early-boot reverse shell/backdoor script auditor.
  - **Userland Interceptor Scanner**: `/etc/ld.so.preload` and PAM dynamic linker hook detection (Azazel, Jynx).
  - **Raw Ext4 Inode Differential Engine**: Cross-view validation comparing raw disk superblock & inode tables against VFS directory trees.
- **Automated ISO Generation (`make iso`)**: Standalone live bootable ISO output ready for USB deployment.

---

## Quick Start & Build Instructions

### Dependencies (Debian / Ubuntu)
```bash
sudo apt-get install -y build-essential libblkid-dev libudev-dev
```

### Build & Run
```bash
# Build the binary (auto-generates version.h)
make all

# Run unit test suite (9 test suites)
make test

# Launch Interactive Zellij-Style Movable TUI
./bin/booto

# View help and options
./bin/booto --help

# Run a dry-run test
./bin/booto --dry-run -V
```

---

## TUI Window Navigation & Shortcuts

| Shortcut | Action | Description |
| :--- | :--- | :--- |
| `Alt + Arrow` / `hjkl` | **Spatial Focus** | Move focus to adjacent pane |
| `Tab` | **Cycle Focus** | Cycle focus through active leaf panes |
| `Alt + M` | **Move / Swap** | Swap active pane position with adjacent pane |
| `Alt + Z` | **Zoom / Maximize** | Toggle full-screen on focused pane |
| `Alt + H` | **Split Horizontal** | Split focused pane into top & bottom |
| `Alt + V` | **Split Vertical** | Split focused pane into left & right |
| `Alt + [` / `Alt + ]` | **Resize Split** | Adjust split ratio of the active node |
| `Space` | **Toggle Target** | Toggle target disk flag / toggle scanner module |
| `Enter` | **Mount / Unmount** | Mount target storage strictly READ-ONLY |
| `Mouse Click` | **Click to Focus** | Focus pane by clicking inside its border |
| `F2` | **Toggle LUKS** | Lock / unlock encrypted persistence partition |
| `F5` | **Start Scan** | Trigger forensic scanning sequence |
| `F10` / `q` | **Exit** | Gracefully shutdown TUI and restore terminal |

---

## Development Milestones

| Stage | Version | Description | Status |
| :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.1.0-alpha` | Project Foundation, Toolchain, Dynamic Versioning & CI/CD | **Completed** |
| **Stage 2** | `v0.1.5-alpha` | Zellij-Style Movable TUI Window Manager (`ncurses` BSP Tree) | **Completed** |
| **Stage 3** | `v0.2.0-alpha` | Target Storage Discovery (`libblkid`) & Safe RO Mounter | **Completed** |
| **Stage 4** | `v0.4.0-beta`  | Modular Detection Engines (LKM, UEFI, Initrd, Preload, Ext4) | **Completed** |
| **Stage 5** | `v0.5.0-rc1`   | Tails-Style LUKS2 Persistence & Case Reporting | *Next* |
| **Stage 6** | `v0.6.0-rc1`   | Dedicated Testing & Fuzzing Harness (Synthetic Disks, ASan) | *Pending* |
| **Stage 7** | `v0.7.0-rc1`   | Advanced CI/CD Matrix, Sanitizers & Code Coverage | *Pending* |
| **Stage 8** | `v0.8.0-rc1`   | Debian Live ISO Packaging (`make iso`) & Automated CD | *Pending* |
| **Stage 9** | `v1.0.0`       | QEMU Empirical Benchmarking & Capstone Defense Evaluation | *Pending* |

---

## License

This project is licensed under the MIT License.
