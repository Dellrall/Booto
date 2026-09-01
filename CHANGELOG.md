# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0-rc1] - 2026-09-01

### Added
- **Tails-Style LUKS2 Encrypted Persistence Subsystem (`include/persistence_mgr.h`, `src/persistence_mgr.c`)**:
  - Detection and lifecycle management of secondary USB encrypted partition (`label: BOOTO_DATA`).
  - Strict amnesic operation by default: unlocks container only upon explicit user request and mounts to `/persistence/` (`0700` permissions).
  - Secure directory structure: `/persistence/cases/`, `/persistence/rules/`, and `/persistence/logs/`.
  - Passphrase zeroization and clean unmount/LUKS lock restoring pure RAM amnesia.
  - Unit test suite in `tests/test_persistence_mgr.c`.
- **Cryptographic Case Report Generator (`include/case_reporter.h`, `src/case_reporter.c`)**:
  - Structured forensic JSON export (`case_<ID>.json`) capturing host disk UUID, scan duration, module detections, and threat severity levels.
  - Human-readable GitHub Flavored Markdown report (`case_<ID>.md`) with executive summary and forensic breakdown.
  - Automatic cryptographic integrity seal generation computing companion `.sha256` checksums.
  - Unit test suite in `tests/test_case_reporter.c`.
- **TUI Persistence Integration**:
  - `F2` global hotkey to toggle encrypted persistence unlock/lock.
  - `F6` global hotkey to export signed JSON/Markdown case reports.

---

## [0.4.0-beta] - 2026-09-01

### Added
- **Modular Forensic Detection Engines Suite (Stage 4 Complete)**:
  - **In-Memory Initramfs Decompressor & Script Auditor (`include/initramfs_auditor.h`, `src/initramfs_auditor.c`)**:
    - Zero-dependency CPIO archive parser extracting `/boot/initrd.img*` in memory without host disk extraction.
    - Early-boot script audit engine flagging reverse shells (`/dev/tcp/`, `bash -i`, `nc -e`, `mkfifo`), silent payload downloaders (`curl -s`, `wget -q`), and ramdisk LKM injections.
    - Unit tests in `tests/test_initramfs_auditor.c`.
  - **Userland `LD_PRELOAD` & PAM Interceptor Scanner (`include/preload_scanner.h`, `src/preload_scanner.c`)**:
    - Scans target `/etc/ld.so.preload` and dynamic linker search paths in `/etc/ld.so.conf.d/*.conf` for active userland shared library hooks (e.g. Azazel, Jynx, libprocesshider).
    - Computes SHA-256 signatures of referenced shared objects.
    - Unit tests in `tests/test_preload_scanner.c`.
  - **Raw Ext4 Inode vs VFS Cross-View Differential Engine (`include/ext4_diff.h`, `src/ext4_diff.c`)**:
    - Direct byte-level parser for Ext4 superblocks (`0xEF53`) and inode tables.
    - Performs cross-view differential analysis between raw physical disk inodes and mounted VFS directory trees to discover unlinked or hidden rootkit inodes.
    - Unit tests in `tests/test_ext4_diff.c`.

---

## [0.3.5-beta] - 2026-09-01

### Added
- **UEFI & ESP Bootkit Analyzer (Sub-Stage 4B)**:
  - PE32+ (PE/COFF) binary parser (`include/uefi_analyzer.h`, `src/uefi_analyzer.c`).
  - Authenticode Certificate Directory extractor verifying digital signatures on `.efi` loaders.
  - Secure Boot DBX Revocation List matching engine (BlackLotus, BootHole, ESPecter, MoonBounce).
  - Unit test suite in `tests/test_uefi_analyzer.c`.

---

## [0.3.0-beta] - 2026-09-01

### Added
- **ELF Parser & Kernel LKM Rootkit Inspector (Sub-Stage 4A)**:
  - Standalone FIPS 180-4 SHA-256 cryptographic engine (`include/crypto_utils.h`, `src/crypto_utils.c`).
  - Defensive 64-bit ELF Parser (`include/elf_analyzer.h`, `src/elf_analyzer.c`).
  - Kernel LKM & Rootkit Hooking Engine (`include/kernel_inspector.h`, `src/kernel_inspector.c`).
  - Unit test suite in `tests/test_elf_analyzer.c`.

---

## [0.2.0-alpha] - 2026-09-01

### Added
- **Target Storage Discovery & Safe Read-Only Mounter (Stage 3)**:
  - Block device discovery subsystem (`include/disk_mount.h`, `src/disk_mount.c`) reading `/proc/partitions` and `/sys/class/block`.
  - Forensic read-only mounting (`disk_mount_ro()`) enforcing `MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` with the `noload` option.
  - Unit test suite in `tests/test_disk_discovery.c`.

---

## [0.1.5-alpha] - 2026-09-01

### Added
- **Dynamic Zellij-Style TUI Window Manager (Stage 2)**:
  - Zero-dependency double-buffered ANSI/VT100 terminal engine (`include/tui/terminal.h`, `src/tui/terminal.c`).
  - SGR 1006 mouse tracking support for click-to-focus and pane selection.
  - Binary Space Partitioning (BSP) dynamic window tree (`include/tui/wm.h`, `src/tui/wm.c`).
  - Interactive Pane Subsystem (`include/tui/pane.h`, `src/tui/pane.c`).
  - Unit tests for the BSP window manager tree (`tests/test_wm_tree.c`).

---

## [0.1.0-alpha] - 2026-09-01

### Added
- **Project Foundation & Toolchain (Stage 1)**:
  - Strict C11 compiler configuration with hardening flags.
  - Dual build system (`CMakeLists.txt` and `Makefile`).
  - Dynamic Semantic Versioning generation.
  - Structured forensic logging subsystem.
  - Zero-dependency C11 unit testing framework (`tests/test_framework.h`).
  - GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`).
