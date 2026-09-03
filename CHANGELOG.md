# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-09-03

### Added
- **Direct Superblock Magic Byte Probing**:
  - Implemented `disk_probe_fs_magic()` in `src/disk_mount.c` to directly inspect low-level filesystem superblock signatures via `pread()` on raw disk blocks.
  - Added native signature support for:
    - **Ext4**: Superblock magic `0xEF53` at offset 1024 with embedded volume label extraction.
    - **FAT12 / FAT16 / FAT32 (vfat)**: BPB boot signature `0x55AA` and OEM filesystem identifiers at offsets 54 and 82.
    - **NTFS**: Volume OEM ID `"NTFS    "` at offset 3.
    - **XFS**: Magic header `"XFSB"` at offset 0 with 12-character filesystem label extraction.
    - **Btrfs**: Superblock signature `"_BHRfS_M"` at offset 65,536 (64 KB).
    - **ISO9660**: Volume descriptor identifier `"CD001"` at offset 32,768 (32 KB).
  - Clean trailing whitespace trimming on extracted volume labels.
  - Added comprehensive 7-scenario unit test suite in `tests/test_disk_discovery.c`.

---

## [1.1.0] - 2026-09-03

### Added
- **MBR, Track 0 Slack Gap & VBR Bootkit Detection Engine (Sub-Stage 4F)**:
  - Direct sector-level offline analysis of Sector 0 (MBR), Track 0 unpartitioned slack space (LBA 1..63 / 2047), and partition Volume Boot Records (VBR).
  - Signature and heuristic detection for classic and advanced bootkits: **Rovnix / Carberp MBR**, **TDL4 / Sinowal (Mebroot)**, **Stoned / Legacy Bootkits**, **GAPZ / Cidox VBR hooks**, and **HermeticWiper / Ransomware MBR wipers**.
  - Structural anomaly heuristics: Invalid `0x55AA` signatures, corrupt partition status bytes, multiple active/bootable partitions, and direct BIOS INT 13h disk-write instructions in MBR code.
  - Automated bootloader fingerprint classification (`GRUB 2`, `GRUB Legacy`, `Syslinux/ISOLINUX`, `Windows NT 6+`, `Windows Legacy`, `LILO`).
  - Unit test suite (`tests/test_mbr_auditor.c`), 500-iteration mutation fuzzing harness (`tests/test_fuzz.c`), and threat rules (`rules/mbr_bootkit_signatures.json`).
  - Integrated into the 6-module TUI scan sequence (`F5: Scan`) and cryptographic case reporting (`F6: Export Report`).

---

## [1.0.9] - 2026-09-02

### Added
- **Interactive System Power & Exit Menu**:
  - Added dedicated power management modal triggered by `F10`, `Q`, `Ctrl+C`, `Ctrl+Q`, or `Ctrl+X`.
  - Direct actions to **Power Off (`P`)**, **Reboot (`R`)**, **Drop to Root Bash Shell (`S`)**, or **Cancel (`Esc`)**.
  - Updated Live ISO `getty@tty1` service to drop into an interactive root bash prompt on exit rather than restarting in an infinite loop.

---

## [1.0.8] - 2026-09-02

### Fixed
- **Pixel-Perfect Column Alignment in Storage Devices Pane**:
  - Aligned table header and device row formats (`Device`, `FS`, `Size`, `Target Status`) with unified fixed-width formatting.

---

## [1.0.7] - 2026-09-02

### Fixed
- **Storage Mounter Auto-Filesystem & Raw Disk Fallback**:
  - Automatically probes candidate filesystems (`ext4`, `vfat`, `ntfs`, `iso9660`, `btrfs`, `xfs`) when mounting storage volumes with unknown filesystem headers.
  - Gracefully falls back to direct raw block and inode analysis when unformatted or unpartitioned virtual hard disks are selected without raising mount failures.

---

## [1.0.5] - 2026-09-02

### Changed
- **Threat Inspector Idle State & Dynamic Target Triage**:
  - Threat Inspector pane now initializes in a clean `IDLE / READY` state on startup, awaiting target scan execution.
  - Pressing `F5` dynamically inspects the selected target storage volume (e.g. `/dev/sda`) and populates real-time forensic findings.
  - Dynamic versioning in `Makefile` now accurately derives the SemVer tag across all live environments.

---

## [1.0.4] - 2026-09-02

### Added
- **Versioned ISO Artifact Naming & Embedded Release Notes**:
  - Live ISO artifacts and checksums are now dynamically named after their release tag (e.g. `booto-v1.0.4-amd64.iso` and `booto-v1.0.4-amd64.iso.sha256`).
  - Automated release pipeline extracts the full changelog body directly into GitHub Releases.

---

## [1.0.2] - 2026-09-02

### Fixed
- **GRUB Automated Kernel Discovery**:
  - Embedded `iso9660`, `part_gpt`, `part_msdos`, `fat`, and `search` drivers into the `BOOTX64.EFI` standalone image.
  - Added `search --no-floppy --set=root --file /live/vmlinuz` to the GRUB configuration to automatically mount the ISO9660 root filesystem across all virtual machine environments.

---

## [1.0.1] - 2026-09-02

### Fixed
- **Universal Dual-Boot Live ISO Assembly**:
  - Formatted a dedicated 16MB FAT `efiboot.img` for El Torito UEFI boot compliance in VirtualBox and hardware UEFI systems.
  - Added Legacy BIOS (`i386-pc`) bootloader support for seamless dual BIOS + UEFI operation.

---

## [1.0.0] - 2026-09-01

### Added
- **Production Milestone & Empirical Benchmark Evaluation (Stage 9 Complete)**:
  - **Empirical Head-to-Head Benchmarking Suite (`scripts/run_benchmarks.sh`, `BENCHMARK_RESULTS.md`)**:
    - Quantitative evaluation comparing Booto against in-system utilities (`chkrootkit`, `rkhunter`) across Diamorphine, Reptile, BlackLotus, Azazel, and unlinked Ext4 inodes.
    - Demonstrates 100% True Positive Rate (TPR) and 0% False Positive Rate (FPR) with ~7x–9x speed improvement and <15 MB peak RAM footprint.
  - **Dynamic Rule & Threat Intelligence Updater (`scripts/update_rules.sh`, `--update-rules`)**:
    - CLI and script updater fetching latest UEFI DBX revocation hashes and Ring-0 rootkit signatures to `/persistence/rules/`.
  - **Full Production Release**: Complete graduation of all 9 engineering stages.

---

## [0.8.0-rc1] - 2026-09-01

### Added
- **Debian Live ISO Packaging & Dual-Partition USB Setup Utility (Stage 8 Complete)**:
  - **Live ISO Builder Engine (`scripts/build_iso.sh`)**:
    - Automated `debootstrap` Debian 12 (Bookworm) `minbase` construction with dual UEFI (`x86_64-efi`) + BIOS bootloaders.
    - Systemd autologin directly launching Booto TUI in pure RAM amnesic mode.
    - SquashFS compression with `xz -Xbcj x86` and hybrid ISO generation via `xorriso`.
  - **Dual-Partition USB Setup Utility (`scripts/setup_usb.sh`)**:
    - Automated partitioning of USB drives:
      - Partition 1 (`BOOTO_LIVE`): FAT32 Amnesic Live OS.
      - Partition 2 (`BOOTO_DATA`): LUKS2 Encrypted Persistence volume with secure `/persistence/{cases,rules,logs}` directory structure.
  - **Automated ISO Build & CD Workflow (`.github/workflows/iso-builder.yml`)**:
    - Automated ISO compilation on GitHub Actions with automatic GitHub Releases publishing.

---

## [0.7.0-rc1] - 2026-09-01

### Added
- **Advanced CI/CD Matrix & Automated Code Coverage (Stage 7 Complete)**:
  - **Multi-Compiler Matrix**: Automated parallel build and test execution across GCC and Clang in GitHub Actions.
  - **Automated Sanitizers & Fuzzing**: AddressSanitizer and UndefinedBehaviorSanitizer integrated directly into CI matrix.
  - **Automated `gcov` Code Coverage Engine (`make coverage`, `scripts/check_coverage.sh`)**:
    - Generates detailed per-file line and branch coverage profiling.
    - Code coverage evaluated across all modules (100% crypto, >90% reporter, >75% UEFI/Preload/ELF).

---

## [0.6.0-rc1] - 2026-09-01

### Added
- **Dedicated Forensic Testing & Fuzzing Harness (Stage 6 Complete)**:
  - **Defensive Mutation Fuzzing Suite (`tests/test_fuzz.c`)**:
    - Over 1,500 randomized mutated and edge-case fuzzing iterations across the 64-bit ELF parser, UEFI PE32+ parser, and CPIO in-memory archive unpacker.
    - Validates defensive handling of truncated buffers, corrupted section headers, out-of-bounds offsets, and cyclic directory tables with 0 segfaults or memory corruptions.
  - **Synthetic Forensic Test Disk Generator (`scripts/gen_mock_disk.sh`)**:
    - Creates standalone multi-partition disk images containing mock UEFI ESP bootloaders, Diamorphine LKM modules, `/etc/ld.so.preload` hooks, and reverse shell initramfs scripts.
  - **Sanitizer Build Targets (`make asan`, `make fuzz`)**:
    - Added AddressSanitizer and UndefinedBehaviorSanitizer build targets (`-fsanitize=address,undefined -g -fno-omit-frame-pointer`).
    - Verified 100% clean execution with 0 memory leaks or pointer violations.

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
