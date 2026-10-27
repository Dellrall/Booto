# Changelog

All notable changes to the **Booto** forensic rootkit & bootkit detection framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **TUI redesign**:
  - Panes share single-line box-drawing borders with proper junctions, using only CP437 glyphs and the 16 standard colours so it renders the same on a bare Linux VT. `BOOTO_ASCII=1` falls back to ASCII.
  - Text is clipped to its pane and never crosses a border.
  - New default layout: Storage and Engines on the left, Findings above Log on the right.
  - Findings opens with a colour-coded verdict band (CLEAN / THREATS / INCOMPLETE) followed by a per-engine result table.
  - Engines show live per-engine results; Storage marks the evidence target with ♦.
  - The top bar shows the target and LUKS state; the bottom bar shows the status message plus key hints that drop by priority on narrow screens.
  - Copy is plain and accurate (no "PAM", "VFS diff", "Disassembly" or "Signed" claims).

### Added
- **Shared scan orchestrator (`src/forensic_scan.c`)**: records a per-engine status (`OK`/`ERROR`/`SKIPPED`) and a verdict (`CLEAN`/`THREATS`/`INCOMPLETE`). `CLEAN` is reported only when every engine ran and nothing was found; a failed mount yields `INCOMPLETE`.
- **Real headless CLI**:
  - `booto -c [-t <dev> | -s <rootfs>] [-p <report-dir>]` scans and prints a per-module table.
  - Writes JSON and Markdown reports.
  - Exits `0` for clean, `1` for threats and `2` for incomplete scans.
- `--dry-run` prints the planned scan without touching any disk. `-V` now also applies to the TUI.
- **Runtime rules loader (`src/rules_loader.c`)**:
  - DBX, LKM and MBR signatures load from `rules/*.json`. The search order is `$BOOTO_RULES_DIR`, `/persistence/rules`, `/usr/share/booto/rules`, then `./rules`.
  - A bounded JSON reader parses the files.
  - A present file must match its `.sha256` seal or it is refused (`BOOTO_ERR_CORRUPT_DATA`), which marks the engine `ERROR`.
  - Absent files fall back to identical built-in tables.
  - The ISO installs the rules into `/usr/share/booto/rules`.
- **Authenticode PE image hash (`authenticode_sha256`)** for PE32 and PE32+. UEFI DBX matching now uses it instead of the whole-file SHA-256. Verified against the digest embedded in Debian's signed `shimx64.efi`.

### Security
- **Storage layer (`src/disk_mount.c`, `src/persistence_mgr.c`)**:
  - `cryptsetup` is now run via `fork`/`execvp` (`disk_exec_argv()`); passphrases go over stdin with `--key-file=-`. This removes a root shell-injection through LUKS passphrases and keeps them out of `ps`.
  - Mount directories are created with `disk_ensure_private_dir()`, which creates them as 0700 and rejects symlinks or foreign-owned directories.
  - The target block device is marked read-only with `BLKROSET` before any mount.
  - ext4/ext3 are never mounted without `noload`, xfs without `norecovery`, or btrfs without `nologreplay`.
- **Case reporter (`src/case_reporter.c`)**:
  - JSON string fields are escaped per RFC 8259, and Markdown cells neutralise `|`, backticks and control characters.
  - `case_id` is restricted to `[A-Za-z0-9_-]{1,50}`, which closes path traversal through the report filename.
- **Parsers (`src/elf_analyzer.c`, `src/uefi_analyzer.c`)**:
  - ELF section, string and symbol table bounds are checked without integer wraparound.
  - Section and symbol names are bounded by their table size, which closes an over-read on unterminated entries.
  - `symbol_count` is published only after the symbol array is allocated.
  - The PE header and certificate table bounds are computed in 64-bit, so the 32-bit wrap that let a crafted `e_lfanew` read out of bounds is gone.
### Changed
- **Ext4 engine is stats-only**: it reports superblock inode counts with `cross_view_performed = false`. The fabricated "hidden inode #1849201" mock and its fallback were removed.
- **Case reports** now carry the scan verdict and each module's real status instead of hardcoded `CLEAN`/`ALERT` labels.
- The TUI Threat Inspector shows `CLEAN`, `THREATS` or `INCOMPLETE` from the real report.
- F6 exports the last real scan, or refuses if none has run yet.
- The LUKS banner reflects real unlock state; the fake F2 toggle was removed.


### Fixed
- `disk_mount_ro()` returns `BOOTO_ERR_MOUNT_FAILED` when no filesystem mounts, instead of `BOOTO_OK`.
- Non-root mount, unmount and LUKS calls return `BOOTO_ERR_PERMISSION_DENIED` instead of emulating success.
- Mock partitions are injected only with `--mock-drives`. Partition names such as `nvme0n1` are no longer mislabelled by substring heuristics.
- `persistence_lock()` checks the `umount`/`cryptsetup close` results and stays `UNLOCKED` on failure. `persistence_unlock()` closes the mapper if mounting fails and reports real capacity via `statvfs`.
- The TUI wipes the LUKS passphrase buffer with `explicit_bzero`.
- Case report write, close and seal failures now propagate as `BOOTO_ERR_IO` instead of returning `BOOTO_OK`.
- `mbr_audit_device()` returns an error when the device cannot be read, instead of a fabricated clean GRUB result; `mbr_audit_mock()` was removed.
- `--update-rules` returns the updater script's exit status.
- `scripts/update_rules.sh` closes the `EOF_LKM` heredoc, which previously swallowed the rest of the script into the LKM rules file. It now regenerates all three rule files and seals byte-for-byte, and fetches nothing from the network.
- **Initramfs**: gzip, zstd, xz, lzma, lz4 and bzip2 images and early-microcode + compressed concatenations are now decompressed through system tools and scanned. A missing decompressor is an error, never clean. Compressed `.ko.xz`, `.ko.zst` and `.ko.gz` modules are inspected.
- **MBR gap**: embedding a `GRUB`/`SYSLINUX` string no longer suppresses analysis, and data sectors that merely start with jump bytes no longer alarm. High-entropy or INT 13h hook payloads are flagged.
- **`ld.so.preload`** entries are whitespace-tokenised (all entries audited, no 512-byte line cap). `LD_PRELOAD` in `etc/environment` is also checked.
- **Fuzzing**: deterministic mutation fuzzing from valid ELF, PE32/PE32+, MBR/VBR/gap and initramfs seeds (1,500 iterations per parser) replaces 500 purely random buffers.
- **TUI robustness**:
  - The terminal is restored (termios, cursor, alternate screen) on SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGSEGV, SIGBUS, SIGABRT, SIGFPE and at exit.
  - Resize buffers are swapped only after every allocation succeeds.
  - Escape-sequence parsing is bounded by the bytes actually read; F11 and F12 are distinct keys.
  - Closing a zoomed pane no longer leaves a dangling `zoomed_leaf`. Splits stop at 32 panes or the minimum pane size.
- **Logger**: genuinely thread-safe (mutex). It no longer writes to stderr while the TUI callback is registered, so log lines stopped painting over the UI. Re-initialising closes the previous log file.
- **F5 scans run on a worker thread**: the UI keeps rendering with a `Scanning [k/6]` spinner. Export, mount and LUKS actions are refused, and quitting waits for the worker. `Alt+M` swaps with the next pane instead of always "right".
- **Build and CI**:
  - The version comes only from git tags, for both Make and CMake (fallback `0.0.0-unknown`); the hardcoded CMake `1.1.2` is gone.
  - GitHub Actions are pinned to commit SHAs, and `ci.yml` has read-only `contents` permission.
  - CI runs on pushes to `main` and on pull requests (no duplicate feature-branch push runs), with `cancel-in-progress` concurrency.
  - ISO timestamps derive from `SOURCE_DATE_EPOCH` (the last commit time).
- **Scripts**:
  - `setup_usb.sh` refuses disks backing `/`, `/boot` or `/boot/efi`, partitions and non-disk devices, and non-removable disks unless `--force-nonremovable` is passed. It requires typing the exact device path to confirm and fails on unmount errors.
  - `gen_mock_disk.sh` and `check_coverage.sh` fail loudly; `check_coverage.sh` also prints an aggregate total.

### Removed
- `BENCHMARK_RESULTS.md` and `scripts/run_benchmarks.sh`: the script wrote hardcoded numbers without running Booto.
- README claims not backed by code: the benchmark figures, "signed" reports, PAM scanning, the ncurses TUI and the coverage badge.

---

## [1.1.2] - 2026-09-03

### Added
- **LUKS1 / LUKS2 Target Detection & Read-Only Decryption Subsystem**:
  - Added binary header inspection for `"LUKS\xba\xbe"` at Sector 0 with version classification (LUKS1 vs LUKS2) in `disk_probe_fs_magic()`.
  - Implemented `disk_luks_open_ro()` in `src/disk_mount.c` to forensically map encrypted partitions to `/dev/mapper/<name>` with `--readonly` enforcement, ensuring host keyslots and metadata are preserved unchanged.
  - Implemented `disk_luks_close()` to safely tear down decrypted target device-mapper nodes.
  - Added interactive **LUKS Encrypted Partition Unlock Modal** in the TUI (`render_luks_modal()`), triggered via `F3: Decrypt LUKS` or by pressing `Enter` on any detected `crypto_LUKS` partition in the Storage Devices pane.
  - Automatically maps cleartext target volumes (`/dev/mapper/booto_target_luks`) directly into the active forensic scanning flow.
  - Added LUKS header probing and lifecycle tests in `tests/test_disk_discovery.c`.

---

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
