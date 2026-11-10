# Booto agent notes

Booto is a C11 offline rootkit/bootkit scanner that runs from a Debian 12 live USB. User docs: `README.md`, `docs/SETUP.md`; man pages in `man/`. Build and test targets are in the `Makefile`.

## Invariants

- **Read-only targets.** Every mount of a scan target uses `MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID` (plus `noload` / `nologreplay` where the filesystem has a journal). A write to a target is a security bug (`SECURITY.md`).
- **Honest verdicts.** An engine that cannot run sets the scan `INCOMPLETE`, never `CLEAN`.
- **Parsers face hostile input.** Disk, PE, ELF, initramfs, hive and rule parsers bound every read; new parser code gets a case in `tests/test_fuzz.c`.
- **Raw termios TUI.** `src/tui/` draws with ANSI and CP437 glyphs, 16 colours; ncurses stays out.

## Checks

Run `make test` before every commit; `make asan` and `make zoo` before a PR that touches a scan engine. CI also runs fuzzing, gcov, cbmc and a multi-compiler build.

## Rules

`rules/*.json` and `rules/bootkits.yar` are Ed25519-signed (`*.sig`). After editing them, the maintainer re-signs with `BOOTO_RULES_SIGNING_KEY=<key.pem> scripts/update_rules.sh rules`; the key lives off-repo, so ask the maintainer to run it.

## ISO

`scripts/build_iso.sh` compiles `booto` inside the Debian 12 rootfs so it links only libraries the live system ships. A package added to the binary's link line also goes in the debootstrap `--include` list.

## Git and releases

- One commit per change, one PR per session or phase; PRs merge with `gh pr merge --rebase`. Fix a broken commit with a fixup into that commit.
- Conventional commit subjects: `feat(tui):`, `fix(iso):`, `docs:`.
- Every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md`.
- Release: rename `[Unreleased]` to `[X.Y.Z-beta] - <date>`, update the README milestone table, commit `docs: release X.Y.Z-beta`, push tag `vX.Y.Z-beta`. The tag triggers `.github/workflows/iso-builder.yml`, which builds the ISO and publishes the release from the changelog section.
- Versions carry `-beta` until validated on real hardware against real samples. Fixes bump the patch number; features bump the minor.
- `docs/BLUEPRINT.md` is a local planning file; keep it untracked.
