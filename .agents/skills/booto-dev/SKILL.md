---
name: booto-dev
description: Specialized instructions and workflows for developing, building, testing, versioning, and packaging the Booto C rootkit/bootkit detection engine, Zellij-style movable ncurses TUI, and Debian-based Tails-like Live USB ISO with optional encrypted persistence.
---

# Booto Development & Forensic Verification Skill

This skill serves as the **authoritative architectural specification, coding protocol, and operational manual** for developing, testing, debugging, versioning, and deploying the Booto forensic live operating system and detection engines.

---

## 1. Core Engineering Principles & Architecture

1. **Zero External Dynamic Dependencies**:
   - The core engine is pure C11. It must never rely on heavy external runtimes (e.g., Python, Electron, GLib, Qt).
   - Standard POSIX syscalls and self-contained algorithms only (e.g. custom SHA-256 in `src/crypto_utils.c`, custom ELF parser in `src/elf_analyzer.c`).
2. **Strict Compiler Hardening**:
   - All code must compile warning-free with:
     ```makefile
     -std=c11 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wformat=2 -Wconversion -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
     ```
3. **Forensic Integrity & Strict Read-Only Access**:
   - Target disks must only ever be mounted with `MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` and `noload` to guarantee zero evidence tampering.
   - Unformatted or raw partitions must be audited at the block level without throwing destructive errors.
4. **Defensive Memory Hygiene**:
   - All string formatting into fixed buffers must use precision specifiers (`snprintf(buf, sizeof(buf), "%.100s", src)`).
   - Clear sensitive memory buffers (hashes, keys, passphrases) with memory wipes prior to `free()`.

---

## 2. Standard Recipe for Implementing Any New Detection Module

Every new forensic detection module (e.g. MBR, UEFI, LKM, Preload) must strictly follow this 8-step integration recipe to maintain uniform architecture:

```mermaid
graph LR
    S1[1. Header API include/] --> S2[2. Engine Impl src/]
    S2 --> S3[3. Signatures rules/]
    S3 --> S4[4. Unit Tests tests/]
    S4 --> S5[5. Fuzzing Harness]
    S5 --> S6[6. Case Reporter]
    S6 --> S7[7. TUI Live Scan]
    S7 --> S8[8. Mock Disk & Updater]
```

### Step-by-Step Implementation Checklist:

1. **Header Definition (`include/<module>.h`)**:
   - Define severity enum (`<module>_severity_t`: INFO, LOW, MEDIUM, HIGH, CRITICAL).
   - Define finding struct (`<module>_threat_finding_t` with `threat_name`, `target`, `sha256`, `rule_id`, `severity`, `description`).
   - Define aggregated result struct (`<module>_scan_result_t` with `threats_detected`, count metrics, and array of findings).
   - Declare parsing functions (`<module>_audit_buffer`, `<module>_audit_device`), string conversion helper (`<module>_severity_to_string`), and mock fallback (`<module>_audit_mock`).

2. **Core Implementation (`src/<module>.c`)**:
   - Implement low-level buffer parsing and invariant heuristics (e.g. byte patterns, opcode validation, symbol references).
   - Provide a safe mock fallback (`<module>_audit_mock(scenario, result)`) to support non-root unit testing and CI testbeds.
   - Log critical alerts using `LOG_CRITICAL("[MODULE ALERT] ...")` and audit info using `LOG_INFO(...)`.

3. **Threat Signatures Database (`rules/<module>_signatures.json`)**:
   - Store signature JSON with schema: `name`, `rule_id`, `pattern_hex` / `symbols`, `severity`.
   - Generate SHA-256 seal: `sha256sum rules/<module>_signatures.json > rules/<module>_signatures.json.sha256`.

4. **Standalone Unit Test Suite (`tests/test_<module>.c`)**:
   - Test clean baseline scenarios (e.g., standard GRUB, clean kernel modules).
   - Test synthetic threat samples (e.g., specific bootkits, malicious hooks).
   - Wire target into `Makefile` and `CMakeLists.txt`.

5. **Mutation Fuzzing Harness (`tests/test_fuzz.c`)**:
   - Integrate the parser into `test_fuzz.c` and subject it to 1,500 iterations of randomized, corrupted payloads to prove crash resilience.

6. **Forensic Case Reporter (`include/case_reporter.h` & `src/case_reporter.c`)**:
   - Add `<module>_threats_count` to `forensic_case_summary_t`.
   - Update `case_report_generate_json()` and `case_report_generate_markdown()` to include detection tables for the new module.

7. **TUI Live Scan & Modules Display (`src/tui/tui_app.c` & `src/tui/pane.c`)**:
   - In `src/tui/pane.c`: Add the module to `app->modules[...]` and increment `app->module_count`.
   - In `src/tui/tui_app.c`: Invoke the module inside `execute_forensic_scan()`, aggregate threats, and update the Threat Inspector card.

8. **Synthetic Disk & Tooling Integration (`scripts/gen_mock_disk.sh` & `scripts/update_rules.sh`)**:
   - In `scripts/gen_mock_disk.sh`: Inject a synthetic mock sample into the loopback image.
   - In `scripts/update_rules.sh`: Add rule generation and SHA-256 sealing for the new module.

---

## 3. Real-World Lessons Learned & Common Pitfalls

| Subsystem | Common Problem | Proven Solution |
| :--- | :--- | :--- |
| **UEFI & ISO Boot (VirtualBox)** | `No bootable medium found!` in UEFI mode. | `xorriso -e` requires a formatted FAT filesystem image (`efiboot.img`), not raw PE binaries. Include `i386-pc/bios.img` for universal dual BIOS+UEFI boot. |
| **GRUB Kernel Discovery** | `error: file '/live/vmlinuz' not found`. | GRUB `$root` defaults to the EFI partition. Must embed `iso9660`, `part_gpt`, `fat`, `search` modules and run `search --no-floppy --set=root --file /live/vmlinuz`. |
| **Target Disk Mounter** | `Failed to mount /dev/sda: Invalid argument` on fresh VM disks. | New virtual disks contain raw zeroes without partition tables. Probe candidate filesystems (`ext4`, `vfat`, `ntfs`, `iso9660`, `btrfs`, `xfs`) and gracefully fall back to direct raw block/sector analysis. |
| **Systemd Getty Loop** | TUI restart loop when pressing F10/Q. | Live OS `getty@tty1.service.d/override.conf` must use `Restart=no` and `ExecStart=-/bin/bash -c "/usr/local/bin/booto; exec /bin/bash"`. |
| **Terminal Alignment** | Table headers and data rows shifted by 2–3 characters. | Ensure printf format string widths match character-by-character (e.g. `%-20.20s %-8.8s %-9.9s %-16.16s` in both header and row). |
| **GCC Format Truncation** | `-Werror=format-truncation` build failure. | Always use bounded precision specifiers (`snprintf(dest, sizeof(dest), "%.60s", src)`). |

---

## 4. CI/CD Architecture, Git Flags & Commit Conventions

### Conventional Commit Format:
Use structured commit prefixes:
- `feat(scope): ...` — New detection engine, TUI feature, or tool.
- `fix(scope): ...` — Bug fix, memory leak fix, or bootloader correction.
- `docs(scope): ...` — Markdown documentation, skill files, or worklogs.
- `test(scope): ...` — Unit test, fuzzing, or benchmark additions.
- `chore(scope): ...` — Build script, gitignore, or dependency tweaks.

### Commit Flags (Saving Runner Time & Quota):

| Flag in Commit Message | CI/CD Behavior | Best Used When |
| :--- | :--- | :--- |
| **`[skip ci]`** or **`[ci skip]`** | Skips **all** CI tests and ISO builds completely. | Editing documentation, README, `.gitignore`, comments, or worklogs. |
| **`[skip iso]`** or **`[no iso]`** | Runs compiler matrix & unit tests, but skips the 3-minute Debian ISO build. | Testing C code logic, refactoring, or adding unit tests before tagging releases. |

### Automated Path Filtering:
GitHub Actions automatically ignores runs when commits only modify:
- `**.md`, `docs/**`, `.agents/**`, `LICENSE`, `.gitignore`.

### Version Tagging & Automated Release Protocol:
1. Update version entries in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`.
2. Commit changes: `git commit -m "chore(release): prepare vX.Y.Z"`
3. Create annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z: Summary"`
4. Push tag to GitHub: `git push origin main --tags`
5. The ISO builder will automatically compile `booto-vX.Y.Z-amd64.iso`, extract the changelog section, and publish the GitHub Release.

---

## 5. Build, Lint & Test Commands Reference

### Standard Compilation:
```bash
make clean all
```

### Run Unit Tests & Mutation Fuzzing:
```bash
make test
make fuzz
```

### AddressSanitizer & UndefinedBehaviorSanitizer:
```bash
make asan && ./build/test_mbr_auditor && ./build/test_fuzz
```

### Code Coverage Analysis (gcov):
```bash
make coverage
```

### Build Live Debian ISO Locally:
```bash
sudo ./scripts/build_iso.sh booto-live-amd64.iso
```

### Run QEMU Virtual Machine Testbed:
```bash
./scripts/run_qemu_vm.sh ~/Downloads/booto-v1.1.0-amd64.iso
```

---

## 6. Strategic Future Roadmap

- **Stage 10: Companion Rust-Based USB Flasher (`booto-flasher`)**:
  - Memory-safe USB drive discovery, streaming block writer with `indicatif` progress bar, and dual-partition provisioning.
- **Stage 11: Tails/CAINE-Style XFCE4 Desktop Forensic Workstation (`booto-desktop`)**:
  - Debian Live XFCE desktop session with graphical `booto-gui` dashboard and pre-packaged offline DFIR tools (GHex, GParted).
- **Stage 12: Offline Machine-Learning Anomaly Classifier**:
  - Pure C mathematical Shannon entropy ($H = -\sum p_i \log_2 p_i$) and section heuristic classifier for zero-day polymorphic rootkits.
- **Stage 13: Self-Hosted Runner Infrastructure & Zero-Quota Local Builds**:
  - Local Linux x86_64 runners (`runs-on: [self-hosted, linux]`) providing 0-minute cloud billing and sub-minute ISO creation.

