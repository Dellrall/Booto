# Booto

[![CI](https://github.com/Dellrall/Booto/actions/workflows/ci.yml/badge.svg)](https://github.com/Dellrall/Booto/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue.svg)](CHANGELOG.md)
[![Standard](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Booto** is an amnesic, Tails-inspired Live Linux forensic framework designed for **out-of-band offline rootkit and bootkit detection**. 

Built with low-level **C11**, Booto operates from a trusted Debian Live USB environment, bypassing all runtime kernel-space (Ring-0) and userland evasion techniques to conduct strict read-only forensic analysis of host storage devices.

---

## Key Features

- **Amnesic Live OS (Debian 12 Base)**: Runs 100% in RAM (`SquashFS` + `OverlayFS`) with zero host disk tampering.
- **Optional Encrypted Persistence (LUKS2)**: Tails-style secondary encrypted partition to securely preserve forensic logs, case reports, and custom detection rules.
- **Zellij-Inspired Movable TUI**: Terminal User Interface with a dynamic Binary Space Partitioning (BSP) window manager supporting movable, resizable, and zoomable workspace panes.
- **Low-Level Forensic Detection Modules**:
  - UEFI & ESP Bootkit Analyzer (Authenticode, Secure Boot DB/DBX validation).
  - Kernel Image & LKM Hook Scanner (ELF parser, hidden `.ko` modules, exported symbols).
  - In-Memory Initramfs Decompressor & Script Auditor.
  - Userland `LD_PRELOAD` and PAM Interceptor Scanner.
  - Raw Ext4 Inode vs VFS Directory Table Differential Cross-View Scanner.
- **Automated ISO Generation (`make iso`)**: Standalone live bootable ISO output ready for USB deployment.

---

## Architecture Overview

```
Live USB Drive (e.g. /dev/sdb)
├── Partition 1: Debian Live ISO (SquashFS / RAM Base - Read-Only)
└── Partition 2: LUKS2 Encrypted Persistence (Optional Case Reports & Rules)
```

---

## Quick Start & Build Instructions

### Dependencies (Debian / Ubuntu)
```bash
sudo apt-get install -y build-essential libncurses-dev libblkid-dev libudev-dev
```

### Build & Run
```bash
# Build the binary (auto-generates version.h)
make all

# Run unit test suite
make test

# View help and options
./bin/booto --help

# Run a dry-run test
./bin/booto --dry-run -V
```

---

## Development Milestones

| Stage | Version | Description | Status |
| :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.1.0-alpha` | Project Foundation, Toolchain, Dynamic Versioning & CI/CD | **Completed** |
| **Stage 2** | `v0.1.5-alpha` | Zellij-Style Movable TUI Window Manager (`ncurses` BSP Tree) | *Next* |
| **Stage 3** | `v0.2.0-alpha` | Target Storage Discovery (`libblkid`) & Safe RO Mounter | *Pending* |
| **Stage 4** | `v0.3.0-beta`  | Modular Detection Engines (LKM, UEFI, Initrd, Preload, Ext4) | *Pending* |
| **Stage 5** | `v0.5.0-rc1`   | Tails-Style LUKS2 Persistence & Case Reporting | *Pending* |
| **Stage 6** | `v1.0.0`       | Debian Live ISO Packaging (`make iso`) & QEMU Benchmarks | *Pending* |

---

## License

This project is licensed under the MIT License.
