# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0-beta] - 2026-09-01

### Added
- **ELF Parser & Kernel LKM Rootkit Inspector (Sub-Stage 4A)**:
  - Zero-dependency standalone FIPS 180-4 SHA-256 cryptographic engine (`include/crypto_utils.h`, `src/crypto_utils.c`) for binary integrity verification.
  - Defensive 64-bit ELF Parser (`include/elf_analyzer.h`, `src/elf_analyzer.c`) parsing ELF headers, section tables (`.text`, `.rodata`, `.symtab`, `.strtab`, `.modinfo`), symbol tables, and module metadata with strict buffer boundary checks.
  - Kernel LKM & Rootkit Hooking Engine (`include/kernel_inspector.h`, `src/kernel_inspector.c`):
    - `sys_call_table` tampering and dynamic symbol lookup (`kallsyms_lookup_name`) detection.
    - Diamorphine & derivative signatures (`hacked_kill`, `hacked_getdents`, `is_invisible`, `hide_proc`).
    - Ftrace and Kprobes hijacking (`fh_install_hook`, `khook_init`, `rep_hook`, `suterusu`).
    - Hidden network port interceptor rules (`tcp4_seq_show`, `udp4_seq_show`).
    - Recursive directory scanning across target `/lib/modules/` directories.
  - Unit test suite in `tests/test_elf_analyzer.c` validating SHA-256 test vectors, binary ELF parsing, and synthetic rootkit detection rules.

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
