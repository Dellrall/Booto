# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-alpha] - 2026-09-01

### Added
- **Project Foundation & Toolchain (Stage 1)**:
  - Strict C11 compiler configuration with hardening flags (`-Wall -Wextra -Werror -Wpedantic -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE`).
  - Dual build system supporting both modern `CMakeLists.txt` and a hardened top-level `Makefile`.
  - Dynamic Semantic Versioning generation via `scripts/gen_version.sh` injecting Git commit hash and build timestamp into `include/version.h`.
  - Structured forensic logging subsystem (`include/logger.h`, `src/logger.c`) with ANSI color console formatting, file output, and UI callback stream hooks.
  - Core CLI entrypoint (`src/main.c`) supporting `--help`, `--version`, `--dry-run`, `--mock-drives`, and `--verbose`.
  - Zero-dependency C11 unit testing framework (`tests/test_framework.h`) with unit tests for versioning and logging.
  - GitHub Actions Continuous Integration pipeline (`.github/workflows/ci.yml`) for automated build, test, static analysis, and memory safety checks.
  - Automated ISO release packaging workflow (`.github/workflows/release-iso.yml`).
