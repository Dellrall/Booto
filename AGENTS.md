# Booto agent notes

Booto is a C11 offline rootkit/bootkit scanner that runs from a Debian 12 live USB. User docs: `README.md`, `docs/SETUP.md`; man pages in `man/`. Build and test targets are in the `Makefile`.

## Invariants

- **Read-only targets.** Every mount of a scan target uses `MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` (plus `noload` / `nologreplay` where the filesystem has a journal). A write to a target is a security bug (`SECURITY.md`).
- **Honest verdicts.** An engine that cannot run sets the scan `INCOMPLETE`, never `CLEAN`.
- **Parsers face hostile input.** Disk, PE, ELF, initramfs, hive and rule parsers bound every read; new parser code gets a case in `tests/test_fuzz.c`.
- **Raw termios TUI.** `src/tui/` draws with ANSI and CP437 glyphs, 16 colours; ncurses stays out.

## Layout

- `src/<engine>.c` + `include/<engine>.h`: one scan engine each (`mbr_auditor`, `uefi_analyzer`, `kernel_inspector`, `initramfs_auditor`, `windows_boot`, `yara_scan`, `ntfs_undelete`, ...). `forensic_scan.c` runs them all and flattens findings; `main.c` is the CLI.
- `src/tui/`: `terminal.c` (raw input, SGR mouse), `wm.c` + `pane.c` (window tree), `evdev_ptr.c` (console mouse), `tui_app.c` (screens).
- `tests/test_<engine>.c` per engine, using the macros in `tests/test_framework.h`; `tests/zoo/` holds end-to-end infected images built by `scripts/gen_mock_disk.sh`.

## Findings

- Each finding has a rule ID (`UEFI_*`, `LKM_*`, `MBR_*`, `WIN_*`, `ACCT_*`, ...) and a `SEVERITY_*` from `include/booto.h`. `make test` runs `scripts/check_man.sh`, which fails when a rule ID or CLI option has no entry in `man/booto-checks.7` / `man/booto.1`; a new or re-graded rule updates the man page in the same commit.
- False positives are fixed by narrowing the rule or lowering severity, keeping the finding visible: HIGH is for what a bootkit does, MEDIUM for what a legitimate setup also does (DKMS modules, unsigned later-stage EFI loaders, plain `curl` in dracut). Each fix gets a test asserting both the benign and the malicious case.

## Checks

Run `make test` before every commit; `make asan` and `make zoo` before a PR that touches a scan engine. CI also runs fuzzing, gcov, cbmc and a multi-compiler build.

- `CFLAGS` has `-Werror -Wextra -Wconversion`: a struct initializer table that adds a field needs it on every row (`-Wmissing-field-initializers`).
- TUI smoke test: drive `bin/booto -m` (mock drives) through a Python `pty.fork()` with `TIOCSWINSZ`. In the F10 exit modal only `q` is safe: `p`/`1` powers off and `r`/`2` reboots the host running the test.
- Boot test: `scripts/run_qemu_vm.sh [iso]` boots the newest `dist/*.iso` with a mock infected disk. A splash or GPU fix still needs a real-hardware run; VMs pass where i915 machines fail.

## Rules

`rules/*.json` and `rules/bootkits.yar` are Ed25519-signed (`*.sig`). After editing them, the maintainer re-signs with `BOOTO_RULES_SIGNING_KEY=<key.pem> scripts/update_rules.sh rules`; the key lives off-repo, so ask the maintainer to run it.

## ISO

`scripts/build_iso.sh` compiles `booto` inside the Debian 12 rootfs so it links only libraries the live system ships. A package added to the binary's link line also goes in the debootstrap `--include` list.

- Build-only packages are purged after compiling; the live system must not need them at runtime.
- `update-initramfs` runs in the chroot, where `/dev` and `/dev/pts` are absent: a hook that probes devices (lvm2) fails the build, so such hooks are removed before regenerating the initrd.
- Anything the boot splash needs before the root mounts (GPU driver, plymouth theme, font) has to be in the initrd, not only the rootfs.

## Git and releases

- One commit per change, one PR per session or phase; PRs merge with `gh pr merge --rebase`. Fix a broken commit with a fixup into that commit.
- Conventional commit subjects: `feat(tui):`, `fix(iso):`, `docs:`.
- Every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md`.
- Release: rename `[Unreleased]` to `[X.Y.Z-beta] - <date>`, update the README milestone table, commit `docs: release X.Y.Z-beta`, push tag `vX.Y.Z-beta`. The tag triggers `.github/workflows/iso-builder.yml`, which builds the ISO and publishes the release from the changelog section.
- Versions carry `-beta` until validated on real hardware against real samples. Fixes bump the patch number; features bump the minor.
- `docs/BLUEPRINT.md` is a local planning file; keep it untracked.
