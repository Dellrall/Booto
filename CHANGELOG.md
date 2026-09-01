# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0-alpha] - 2026-09-01

### Added
- **Target Storage Discovery & Safe Read-Only Mounter (Stage 3)**:
  - Block device discovery subsystem (`include/disk_mount.h`, `src/disk_mount.c`) reading `/proc/partitions` and `/sys/class/block` to enumerate NVMe, SATA, and USB storage volumes.
  - Forensic read-only mounting (`disk_mount_ro()`) enforcing `MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` with the `noload` option (preventing ext4 journal replay from modifying disk timestamps).
  - Dynamic integration with TUI Storage Devices pane for live drive selection and mount/unmount toggling.
  - Mock device emulator for non-root unit testing and virtualization environments.
  - Human-readable byte formatting helper (`disk_format_size()`).
  - Unit test suite in `tests/test_disk_discovery.c`.

---

## [0.1.5-alpha] - 2026-09-01

### Added
- **Dynamic Zellij-Style TUI Window Manager (Stage 2)**:
  - Zero-dependency double-buffered ANSI/VT100 terminal engine (`include/tui/terminal.h`, `src/tui/terminal.c`).
  - SGR 1006 mouse tracking support for click-to-focus and pane selection.
  - Binary Space Partitioning (BSP) dynamic window tree (`include/tui/wm.h`, `src/tui/wm.c`) supporting splits (`Alt+H`/`Alt+V`), swap (`Alt+M`), zoom (`Alt+Z`), and resize (`Alt+[`/`Alt+]`).
  - Interactive Pane Subsystem (`include/tui/pane.h`, `src/tui/pane.c`).
  - Unit tests for the BSP window manager tree (`tests/test_wm_tree.c`).

---

## [0.1.0-alpha] - 2026-09-01

### Added
- **Project Foundation & Toolchain (Stage 1)**:
  - Strict C11 compiler configuration with hardening flags (`-Wall -Wextra -Werror -Wpedantic -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE`).
  - Dual build system supporting both modern `CMakeLists.txt` and a hardened top-level `Makefile`.
  - Dynamic Semantic Versioning generation via `scripts/gen_version.sh` injecting Git commit hash and build timestamp into `include/version.h`.
  - Structured forensic logging subsystem (`include/logger.h`, `src/logger.c`).
  - Core CLI entrypoint (`src/main.c`).
  - Zero-dependency C11 unit testing framework (`tests/test_framework.h`).
  - GitHub Actions Continuous Integration pipeline (`.github/workflows/ci.yml`).
  - Automated ISO release packaging workflow (`.github/workflows/release-iso.yml`).
