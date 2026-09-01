# Booto

[![CI](https://github.com/Dellrall/Booto/actions/workflows/ci.yml/badge.svg)](https://github.com/Dellrall/Booto/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.2.0--alpha-blue.svg)](CHANGELOG.md)
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
  - UEFI & ESP Bootkit Analyzer (Authenticode, Secure Boot DB/DBX validation).
  - Kernel Image & LKM Hook Scanner (ELF parser, hidden `.ko` modules, exported symbols).
  - In-Memory Initramfs Decompressor & Script Auditor.
  - Userland `LD_PRELOAD` and PAM Interceptor Scanner.
  - Raw Ext4 Inode vs VFS Directory Table Differential Cross-View Scanner.
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

# Run unit test suite
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
| `F5` | **Start Scan** | Trigger simulated forensic scanning sequence |
| `F10` / `q` | **Exit** | Gracefully shutdown TUI and restore terminal |

---

## Development Milestones

| Stage | Version | Description | Status |
| :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.1.0-alpha` | Project Foundation, Toolchain, Dynamic Versioning & CI/CD | **Completed** |
| **Stage 2** | `v0.1.5-alpha` | Zellij-Style Movable TUI Window Manager (`ncurses` BSP Tree) | **Completed** |
| **Stage 3** | `v0.2.0-alpha` | Target Storage Discovery (`libblkid`) & Safe RO Mounter | **Completed** |
| **Stage 4** | `v0.3.0-beta`  | Modular Detection Engines (LKM, UEFI, Initrd, Preload, Ext4) | *Next* |
| **Stage 5** | `v0.5.0-rc1`   | Tails-Style LUKS2 Persistence & Case Reporting | *Pending* |
| **Stage 6** | `v1.0.0`       | Debian Live ISO Packaging (`make iso`) & QEMU Benchmarks | *Pending* |

---

## License

This project is licensed under the MIT License.
