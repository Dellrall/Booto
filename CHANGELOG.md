# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.5-beta] - 2026-09-01

### Added
- **UEFI & ESP Bootkit Analyzer (Sub-Stage 4B)**:
  - PE32+ (PE/COFF) binary parser (`include/uefi_analyzer.h`, `src/uefi_analyzer.c`) extracting DOS headers, COFF machine architecture, entry points, and optional header data directories.
  - Authenticode Certificate Directory extractor verifying whether `.efi` bootloaders possess valid embedded digital signatures.
  - Secure Boot DBX Revocation List matching engine (detecting BlackLotus CVE-2022-21894/CVE-2023-24932 revoked Windows bootloaders, BootHole CVE-2020-10713 vulnerable GRUB2 shims, ESPecter, and MoonBounce stage-2 loaders).
  - ESP directory scanner recursively auditing `/boot/efi/EFI/` and flagging unsigned/revoked binaries.
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
