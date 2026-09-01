# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.5-alpha] - 2026-09-01

### Added
- **Dynamic Zellij-Style TUI Window Manager (Stage 2)**:
  - Zero-dependency double-buffered ANSI/VT100 terminal engine (`include/tui/terminal.h`, `src/tui/terminal.c`) with differential screen redraws to eliminate flickering.
  - SGR 1006 mouse tracking support for click-to-focus and pane selection.
  - Binary Space Partitioning (BSP) dynamic window tree (`include/tui/wm.h`, `src/tui/wm.c`) supporting:
    - Split Horizontal (`Alt+H`) and Split Vertical (`Alt+V`).
    - Pane Swap / Move mode (`Alt+M`).
    - Maximize / Zoom mode (`Alt+Z`).
    - Dynamic Split Ratio Adjustment (`Alt+[` / `Alt+]`).
    - Spatial directional focus navigation (`Alt+Arrow` / `hjkl` / `Tab`).
    - Terminal resize handling (`SIGWINCH`) with auto-recalculated layout.
  - Interactive Pane Subsystem (`include/tui/pane.h`, `src/tui/pane.c`):
    - Target Storage Devices pane with drive selector cursor and read-only mount trigger.
    - Forensic Scanner Modules checklist pane.
    - Live Scan & Event Stream pane hooked to logger callbacks.
    - Threat Inspector pane with malware details and hex preview.
    - LUKS Persistence & Case Reports pane with unlock trigger (`F2`).
  - Unit tests for the BSP window manager tree (`tests/test_wm_tree.c`).

---

## [0.1.0-alpha] - 2026-09-01

### Added
- **Project Foundation & Toolchain (Stage 1)**:
  - Strict C11 compiler configuration with hardening flags (`-Wall -Wextra -Werror -Wpedantic -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE`).
  - Dual build system supporting both modern `CMakeLists.txt` and a hardened top-level `Makefile`.
  - Dynamic Semantic Versioning generation via `scripts/gen_version.sh` injecting Git commit hash and build timestamp into `include/version.h`.
  - Structured forensic logging subsystem (`include/logger.h`, `src/logger.c`).
  - Core CLI entrypoint (`src/main.c`) supporting `--help`, `--version`, `--dry-run`, `--mock-drives`, and `--verbose`.
  - Zero-dependency C11 unit testing framework (`tests/test_framework.h`).
  - GitHub Actions Continuous Integration pipeline (`.github/workflows/ci.yml`).
  - Automated ISO release packaging workflow (`.github/workflows/release-iso.yml`).
