# Booto vs. similar tools

Research date: 2026-11-03. Every claim below links its primary source. Three surveys were merged:
- Linux rootkit scanners and integrity checkers;
- firmware and boot-chain tools;
- live and offline forensic environments.

## Summary

**Where Booto is ahead**
- **It scans offline.** Almost every Linux rootkit scanner (chkrootkit, rkhunter, unhide, Wazuh, Sandfly, LKRG) runs on the suspect kernel. A kernel rootkit can hide from those tools; it cannot hide from Booto, which never runs that kernel.
- **Its verdicts are honest.** CLEAN is given only when every engine ran. Classic scanners report "nothing found" even when a check could not run.
- **Its firmware checks overlap fwupd HSI and go further.** Booto also checks KEK/db test keys, setup mode, SMRAM D_LCK, SMRR, AMD TSEG and Thunderbolt DMA protection, with no Python or daemon.
- **It is a single GPL-3.0-or-later C binary with sealed rules.** Most comparable tools are GPL, AGPL or closed.

**Where Booto is behind (fix first)**
1. **The dbx rules are not real revocation data.** None of the 5 hashes in `rules/uefi_dbx_revocations.json` appear in Microsoft's dbx. Two contain filler patterns (`…0123ef…`). The MoonBounce entry describes an SPI-flash implant as an ESP file. Replace them with hashes generated from [`microsoft/secureboot_objects`](https://github.com/microsoft/secureboot_objects) (BSD-2-Clause-Patent).
2. **The live ISO can be tricked into booting the suspect disk.**
   - GRUB uses `search --file /live/vmlinuz` (`scripts/build_iso.sh`), and live-boot is passed no `live-media=` restriction, so a `/live` tree planted on the suspect disk can be booted instead.
   - CAINE patched the same class of issue.
   - Fix: search by label/UUID, and add `live-media=removable verify-checksums`.
3. **There is no package integrity check.** debsums/`rpm -V`-style comparison of installed files against the package database is the cheapest high-value engine missing.
4. **Evidence handling is thin.**
   - Only the mounted device is set read-only, whereas CAINE blocks every disk at boot.
   - There is no examiner or evidence-number metadata.
   - Nothing is hashed before and after the scan to prove the disk was untouched.
5. **There is no memory forensics.** That is out of scope for a boot-time tool, but documenting an AVML capture before shutdown closes the workflow gap.

**Ranked ideas** (value/effort; details in each section's "Top ideas")

| # | Idea | Effort |
|---|---|---|
| 1 | Generate dbx rules from Microsoft's JSON; flag revoked binaries on the ESP | ~1 day |
| 2 | Harden ISO boot: label/UUID search + `live-media=removable verify-checksums` | ~1 hour |
| 3 | Offline package integrity (dpkg `*.md5sums`, `rpm -V` equivalent) | ~2 days |
| 4 | Known-rootkit path and string rules (seeded from BSD-licensed chkrootkit) | ~1 day |
| 5 | Boot-chain anomaly checks: Bootkitty `grubx64-real.efi`, BlackLotus ESP layout, MOK list, SBAT level | ~2 days |
| 6 | Persistence sweep: systemd units, cron, udev, `modules-load.d`, `authorized_keys` | ~1 day |
| 7 | Block every disk read-only at boot; before/after hashes; case metadata flags | ~1 day |
| 8 | Close cheap HSI gaps: BIOSWE, 2023 Microsoft certificate in db, dbx freshness | ~half day |

**Status on 2026-11-09** (what has shipped from the ideas in this document)

| # | Idea | State |
|---|---|---|
| 1 | dbx rules from Microsoft's JSON | done: `scripts/gen_dbx_rules.py`, built-in table plus sealed `rules/uefi_dbx_revocations.json` |
| 2 | Harden ISO boot | done: GRUB looks for a marker file unique to each build, plus `live-media=removable systemd.swap=no`. Still to do: `verify-checksums` |
| 3 | Offline package integrity | done: dpkg `md5sums`, RPM `rpmdb.sqlite` digests, pacman `mtree` |
| 4 | Known-rootkit path and string rules | paths done (`rules/rootkit_file_iocs.json`, `IOC_*`); string rules still to do |
| 5 | Boot-chain anomaly checks | done: shadow loaders, BlackLotus ESP layout, MOK list, SBAT level, Authenticode hash. Still to do: judging whether the signer is trusted |
| 6 | Persistence sweep | done: systemd, cron, rc.local, udev, modprobe.d, shell profiles, `authorized_keys`. Still to do: `modules-load.d` |
| 7 | Read-only disks, before/after hashes, case metadata | case metadata (examiner) done. Still to do: read-only for every disk at boot, before/after hashes |
| 8 | Cheap HSI gaps | still to do: BIOSWE, 2023 Microsoft CA in db, dbx freshness |

Still to do from the per-section lists: a baseline/compare mode, YARA rules, the FwHunt rules, bodyfile/mactime output, and a guide to capturing memory with AVML.

Licence note (written while Booto was MIT; Booto is GPL-3.0-or-later since 2026-11-09, so GPL-3.0 and GPL-2.0-or-later code can now be reused, while GPL-2.0-only and AGPL code still cannot; check each project's exact terms before copying): CHIPSEC, rkhunter, unhide, Wazuh, LKRG, AIDE, Lynis, LiME (GPL), Velociraptor (AGPL) and Volatility 3 (non-MIT) are reference only. These can be used under their own licences: chkrootkit (BSD-2), UAC (Apache-2.0), AVML/sbctl (MIT), UEFITool (BSD-2), FwHunt rules (CC0) and `secureboot_objects` (BSD-2-Clause-Patent).

---

# Linux rootkit scanners & integrity checkers vs Booto

Dates were checked on 2026-11-03 against GitHub API, release pages, and project sites. Anything I inferred rather than read in a source is tagged [INFERENCE].

Main finding: almost every tool here runs **live on the suspect host**. Their core technique is either *cross-view* (ps vs /proc vs syscalls, readdir vs stat, bind() vs netstat) or a *baseline/package-DB diff*. Booto's offline boot defeats cross-view hiding by construction. Booto does not yet have their file-integrity and known-IOC breadth.

## chkrootkit
- **What:** a shell script plus small C helpers (chkproc, chkdirs, ifpromisc, chklastlog/chkwtmp/chkutmp). It checks system binaries for trojaning, finds hidden PIDs/dirs, and detects log wiping. https://www.chkrootkit.org/README
- **Mode:** live. `-r dir` sets an alternate root, e.g. `chkrootkit -r /mnt`, but the process/LKM/promisc tests are inherently live. https://www.chkrootkit.org/README
- **Detection:** string signatures in trojaned binaries, known rootkit file paths, /proc vs ps/readdir cross-view, and wtmp/lastlog gaps. It has a hand-curated list of 75 threats; recent additions include BPFDoor, Kovid and Syslogk. https://www.chkrootkit.org/
- **Maintenance/licence:** v0.59, released 2026-01-01 (https://www.chkrootkit.org/). BSD-style 2-clause licence from Pangeia Informatica (https://www.chkrootkit.org/COPYRIGHT), which is MIT-compatible.
- **Booto does better:** boot sector, VBR and ESP coverage; ELF-parsing of `.ko` files; a sealed rule format; the INCOMPLETE verdict; reports with no reliance on the target's `ps`/`strings`.
- **Booto could learn:** `-r`-style offline checks of known-rootkit paths and binary strings are cheap. chkrootkit's permissive licence also makes its path/string IOC list safe to study.

## rkhunter (Rootkit Hunter)
- **What:** a large Bourne-shell scanner. It runs about 40 test groups: known_rkts, properties (file hashes), hidden_procs/ports, loaded/avail modules, deleted_files, startup_files, shared_libs (ld.so.preload), and others. https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz (`files/rkhunter.8`)
- **Mode:** live only. `--rootdir`/`ROOTDIR` is deprecated and ignored: the code just prints "now deprecated" (`files/rkhunter`, `get_rootdir_option`, option parser).
- **Detection:** per-rootkit file/dir/string signatures; Diamorphine, Adore and others appear in the source. It also checks a SHA-256 file-properties DB built with `--propupd`. This DB can optionally be seeded from the package manager via `PKGMGR`. https://sourceforge.net/projects/rkhunter/
- **Maintenance/licence:** last release 1.4.6 on 2018-02-24 (SourceForge RSS; https://sourceforge.net/projects/rkhunter/files/). The project is effectively dormant. Licence is GPL-2.0, so its code cannot be copied into MIT Booto.
- **Booto does better:** actively maintained; works offline; covers the boot chain and firmware; gives deterministic verdicts.
- **Booto could learn:** a `propupd`-style "trust the package DB, then hash" workflow, and a `--list rootkits` style rule catalogue in the TUI.

## unhide
- **What:** a forensic tool that finds processes and TCP/UDP ports hidden by LKM rootkits. https://github.com/YJesus/Unhide (README.txt)
- **Mode:** live only. It needs the running kernel.
- **Detection:** six process techniques: /proc vs ps, procfs walk, syscall scanning (getsid/getpgid/kill...), PID-space brute force, and reverse/quick variants. For ports it brute-forces bind() on every port and compares with ss/netstat. https://raw.githubusercontent.com/YJesus/Unhide/master/README.txt
- **Maintenance/licence:** last release v20240510, published 2024-12-11; last push 2025-08-12 (GitHub API). Licence is GPL-3.0.
- **Booto does better:** unhide covers nothing on disk, boot, or firmware. Booto's offline view does not depend on a rootkit-controlled kernel.
- **Booto could learn:** little directly, since its techniques need a live kernel. If Booto ever adds an optional live "pre-shutdown triage" mode, the PID-brute-force and bind() cross-view are the canonical, cheap techniques.

## OSSEC / Wazuh rootcheck
- **What:** the rootcheck module inside the OSSEC/Wazuh HIDS agent. Results go to a manager that applies rules and raises alerts. https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html
- **Mode:** agent. It scans every 12 h by default.
- **Detection:**
  - hidden PIDs, via getsid/getpgid vs /proc;
  - hidden ports, via bind() vs netstat;
  - stat-size vs read-size mismatch and readdir link-count mismatch (hidden files);
  - hidden files in /dev, odd SUID/world-writable files, promiscuous NICs;
  - `rootkit_files.txt` (known paths) and `rootkit_trojans.txt` (regex strings in binaries).
  (same URL)
- **Maintenance/licence:** Wazuh v4.14.9 was released 2026-10-15 (https://github.com/wazuh/wazuh/releases). It is GPL-2.0, with the engine under AGPL-3.0 (https://github.com/wazuh/wazuh/blob/main/LICENSE). OSSEC 4.4.1 was released 2026-10-18 under GPL-2.0 (https://github.com/ossec/ossec-hids/releases).
- **Booto does better:** no agent; works on a powered-down or untrusted host; covers MBR/ESP/firmware; sealed rules.
- **Booto could learn:** its two plain-text IOC formats, `path ! Name ::` and `binary !regex! desc`, are simple to adopt as JSON rule types. Its static "suspicious permissions" audit (world-writable root-owned files, SUID in odd places) also works offline.

## Sandfly Security
- **What:** a commercial agentless Linux EDR. It connects over SSH, drops a collector, analyses, then removes the collector. https://sandflysecurity.com/blog/how-agentless-linux-edr-detects-rootkits-over-ssh
- **Mode:** agentless, but live: it runs on the suspect host temporarily.
- **Detection:** forensic engines that bypass OS tools to find cross-view discrepancies (cloaked processes, connections, and files). Also covers SSH-key and weak-password auditing (same URL), automatic drift detection added in 5.6 (https://sandflysecurity.com/blog/sandfly-5-6-automatic-drift-detection), and eBPF rootkit detection since 4.0 (https://sandflysecurity.com/blog/sandfly-4-0-new-ssh-credential-and-key-auditing).
- **Maintenance/licence:** v5.8 published 2026-06-28 (https://sandflysecurity.com/blog/sandfly-58-agentless-response-and-ssh-key-management); later notice of deprecating kernels before 3.2 dated 2026-07-14 (https://sandflysecurity.com/blog/tag/product-update). Proprietary. The free side tools are MIT: https://github.com/sandflysecurity/sandfly-processdecloak and https://github.com/sandflysecurity/sandfly-filescan.
- **Booto does better:** no network or credentials needed; boot-chain and firmware audit; open source; works on hosts that won't boot or are encrypted (LUKS unlock).
- **Booto could learn:** drift-vs-baseline per host, and SSH `authorized_keys` auditing. Both work offline on a mounted root. sandfly-filescan's MIT entropy/ELF heuristics for suspicious executables are reusable as ideas.

## LKRG (Linux Kernel Runtime Guard)
- **What:** an out-of-tree kernel module. It does runtime integrity checking of the kernel and detects exploits. https://github.com/lkrg-org/lkrg (README)
- **Mode:** runtime, in-kernel; it enforces, not just scans.
- **Detection:**
  - validates kernel and module code/rodata, SELinux globals, WP/SMEP/SMAP and MSRs against a baseline, periodically or on events;
  - validates process credentials before they are used;
  - restricts usermodehelper;
  - in 1.0.1, checks that newly loaded modules appear in the module list, which catches Singularity hiding on load.
  https://raw.githubusercontent.com/lkrg-org/lkrg/main/README, https://raw.githubusercontent.com/lkrg-org/lkrg/main/CHANGES
- **Maintenance/licence:** 1.0.1 was announced 2026-04-23 (https://www.openwall.com/lists/lkrg-users/2026/04/23/1); last commit 2026-10-31. Licence is GPL-2.0 (https://raw.githubusercontent.com/lkrg-org/lkrg/main/LICENSE).
- **Booto does better:** post-incident offline forensics; boot/firmware layers that LKRG can't see because it loads after boot; no kernel-version coupling.
- **Booto could learn:** add signature rules for current LKM rootkits named in LKRG's changelog, such as Singularity. Report whether the target had LKRG installed (`/etc/modules-load.d/lkrg.conf`, sysctl files) as a hardening signal. [INFERENCE]

## AIDE
- **What:** a file/directory integrity checker. It builds a DB from regex rules, then diffs against it. https://aide.github.io/
- **Mode:** offline-capable, but needs a baseline. `root_prefix` (since v0.16) strips a prefix so you can scan a mounted tree; it "has no effect in compare mode". https://raw.githubusercontent.com/aide/aide/master/doc/aide.conf.5
- **Detection:** hashes (sha256/sha512 and others) plus inode, perm, uid/gid, size, mtime/ctime, ACL, SELinux, xattrs and ext2 attrs. It only detects change relative to a trusted baseline. https://aide.github.io/
- **Maintenance/licence:** v0.19.5, released 2026-10-21/22 (https://aide.github.io/, https://github.com/aide/aide/releases). Licence is GPL-2.0.
- **Booto does better:** needs no prior baseline; knows malicious patterns rather than just change; covers boot sectors, ESP, initramfs contents and firmware.
- **Booto could learn:** an optional `baseline` / `compare` mode that hashes the boot chain (sector 0, VBRs, ESP PEs, kernels, initramfs, `.ko`) to JSON and diffs it on later scans. Booto already computes most of these hashes.

## debsums / `dpkg --verify` / `rpm -V`
- **What:** verify installed package files against the package manager's recorded digests.
- **Mode:** offline-capable:
  - `debsums --root=dir --admindir=dir` (https://manpages.debian.org/unstable/debsums/debsums.1.en.html);
  - `dpkg --verify` with `--root=directory` (https://manpages.debian.org/unstable/dpkg/dpkg.1.en.html);
  - rpm `--root` plus the VERIFY options (https://github.com/rpm-software-management/rpm/blob/master/docs/man/rpm.8.scd).
- **Detection:**
  - debsums: MD5 vs `/var/lib/dpkg/info/*.md5sums`, and can regenerate sums from cached `.deb` files to avoid trusting on-disk lists;
  - rpm -V: size, digest, mode, owner, mtime and more vs rpmdb.
  Both trust a DB that a root attacker can edit, unless sums come from the original packages.
- **Maintenance/licence:**
  - debsums 3.0.2.4 accepted into unstable 2026-04-22; GPL-2+ (https://tracker.debian.org/pkg/debsums).
  - RPM 6.1.0 released 2026-08-20 (https://rpm.org/timeline.html); GPL, with librpm also available as LGPL (https://github.com/rpm-software-management/rpm/blob/master/COPYING).
- **Booto does better:** these tools cover nothing outside packaged files: no boot sectors, ESP, unpackaged `.ko`, or initramfs scripts.
- **Booto could learn:** this is Booto's biggest stated gap. Parsing `var/lib/dpkg/info/*.md5sums` (plain text, `md5  path`) under the mounted root is small C work with no dependency. Flag a mismatch as THREATS for `/bin`, `/sbin`, `/lib*/` and `/usr/lib/modules`. rpmdb is SQLite on modern RPM, which is harder, so do it later.

## Lynis
- **What:** a security auditing and hardening tool (compliance, hardening tips). It is shell-based with test IDs. https://github.com/CISOfy/lynis
- **Mode:** live. A `--rootdir` option exists (https://raw.githubusercontent.com/CISOfy/lynis/master/include/parameters), but most tests query the running system [INFERENCE from the test code].
- **Detection:** mostly posture, not rootkits:
  - BOOT-5116 checks UEFI boot; BOOT-5122 checks for a GRUB password;
  - KRNL-5726 lists loaded modules;
  - MALW-3275/3276 only check whether chkrootkit/rkhunter are installed.
  https://raw.githubusercontent.com/CISOfy/lynis/master/include/tests_boot_services, https://raw.githubusercontent.com/CISOfy/lynis/master/include/tests_malware
- **Maintenance/licence:** 3.1.7 released 2026-06-25; last push 2026-09-16 (https://github.com/CISOfy/lynis/releases). Licence is GPL-3.0.
- **Booto does better:** actual threat detection, raw boot and firmware analysis, silicon-lock checks that Lynis lacks.
- **Booto could learn:** stable per-check IDs (e.g. `BOOT-5122`), a remediation hint per finding, and a summary hardening score. All of these would fit Booto's Markdown case file. GRUB password and Secure Boot posture checks are easy additions to the host firmware audit.

## YARA-based scanners: THOR Lite, Loki / Loki-RS
- **What:**
  - THOR Lite: Nextron's free, closed-source Go scanner. It has filesystem, process and autoruns modules and ships the open signature-base, about 4,000 rules, in encrypted form. https://www.nextron-systems.com/thor-lite/
  - Loki-RS: an open Rust rewrite of Loki that scans files and process memory with YARA-X, plus hash/filename/C2 IOCs. https://github.com/Neo23x0/Loki-RS
- **Mode:** live. Both can also scan a mounted image, e.g. `loki --no-procs --folder ~/image1` (Loki-RS README). Full THOR (not Lite) adds disk/image scan modes (https://thor-manual.nextron-systems.com/en/latest/).
- **Detection:** YARA rules plus IOC hashes and filename regexes. Loki-RS defaults to YARA Forge Core rules and updates them with `loki-util update` (https://github.com/Neo23x0/Loki-RS).
- **Maintenance/licence:**
  - Loki-RS v2.13.1 released 2026-09-27, GPL-3.0. Legacy Python Loki's last release was v0.51.0 on 2023-05-18 (https://github.com/Neo23x0/Loki/releases).
  - THOR's latest changelog entry is 10.7.32, undated (https://thor-manual.nextron-systems.com/en/latest/changelog/log.html); the THOR Lite page was modified 2026-10-21. Its EULA forbids use on third-party networks or in paid engagements (https://www.nextron-systems.com/thor-lite/).
  - signature-base is under the Detection Rule License 1.1 (https://github.com/Neo23x0/signature-base).
  - YARA v4.6.0 (2026-10-27) is BSD-3-Clause; YARA-X v1.22.1 (2026-10-26) (https://github.com/VirusTotal/yara, https://github.com/VirusTotal/yara-x).
- **Booto does better:** boot sectors, ESP Authenticode/DBX, initramfs decompression, firmware audit, and no network or licence restrictions. These scanners are generic malware hunters, not boot-chain tools.
- **Booto could learn:** rule breadth is the gap. A YARA-subset matcher (text/hex strings plus simple conditions) over ELF, `.ko` and initramfs members would let Booto consume Linux-specific DRL-licensed rules. Vendoring libyara (BSD-3) is licence-compatible but breaks zero-dependency. An "autoruns" persistence sweep is also worth adopting.

## Top ideas for Booto (ranked by value/effort)
1. **Offline dpkg integrity check.** Parse `<root>/var/lib/dpkg/info/*.md5sums` and hash the listed files; report mismatches in system binary and module dirs. This closes the largest stated gap with about one small parser plus MD5, and it is what debsums/rkhunter `properties` do.
2. **Known-rootkit path/string IOC rule type.** Add JSON rules of the form `path exists` and `binary contains regex`, seeded from chkrootkit (BSD) and Wazuh-style formats, and from LKRG-named current threats such as Singularity, Kovid, Syslogk and BPFDoor. This is data-heavy rather than code-heavy, cheap, and covers what every competitor checks.
3. **Offline persistence/"autoruns" sweep.** Cover systemd units, cron, rc.local, udev rules, `modules-load.d`, `authorized_keys`, and shell profiles. THOR Lite, Sandfly and rkhunter `startup_files` all do this, and it is just file reads under the mounted root.
4. **Boot-chain baseline/compare mode.** Emit the existing hashes (MBR, VBR, ESP PEs, vmlinuz, initramfs, `.ko`) as JSON and diff them on rescans. This is AIDE/Sandfly-drift value for near-zero new hashing code.
5. **YARA-subset matcher, or optional libyara.** This unlocks thousands of maintained Linux rules (YARA Forge, signature-base under DRL 1.1) and addresses the "small rule sets" limitation. It is the highest effort of the five, so it ranks last.

---

# Firmware & boot-chain security tools vs Booto

Researched 2026-11-03. Maintenance dates come from GitHub release and commit metadata on that date. `[INFERENCE]` marks claims I did not verify from a source.

## CHIPSEC
- **What it is:** a platform-security assessment framework from Intel. It ships `chipsec_main` (test modules) and `chipsec_util` (raw access to SPI, MSR, PCI and UEFI variables). https://chipsec.github.io/usage/Running-Chipsec.html
- **Mode:** live, on the target. It loads its own kernel driver (`--no_driver` only works for some modules). fwupd's HSI spec notes that this means turning off Secure Boot or allowing unsigned modules. https://fwupd.github.io/libfwupdplugin/hsi.html
- **Detection:**
  - Register and lock checks: `bios_wp`, `spi_lock`, `spi_desc`, `smm`, `smrr`, `smm_dma` (TSEG), `memlock`, `debugenabled`, `me_mfg_mode`, `secureboot.variables`, `uefi.s3bootscript`. https://chipsec.github.io/modules/chipsec.modules.common.html
  - `tools.uefi.scan_blocked` dumps SPI flash or takes an image file. It matches EFI modules by GUID, name, MD5/SHA-1/SHA-256 or regex against `blockedlist.json`, which lists HackingTeam rkloader, MosaicRegressor, LoJax, ThinkPwn and FirmwareBleed. https://chipsec.github.io/modules/chipsec.modules.tools.uefi.scan_blocked.html , https://github.com/chipsec/chipsec/blob/chipsec2/chipsec/modules/tools/uefi/blockedlist.json
  - `smm_dma` checks TSEGBaseLock/LimitLock against SMRR. https://chipsec.github.io/modules/chipsec.modules.common.smm_dma.html
- **Maintenance/licence:** v2.0.9 released 2026-09-24; last push 2026-10-22; GPL-2.0, so its code cannot be copied into MIT Booto. https://github.com/chipsec/chipsec/releases/tag/2.0.9
- **Booto does better:**
  - Needs no driver and no Secure Boot downgrade.
  - Scans the disk offline (MBR/VBR, ESP, LKM, initramfs).
  - Produces case-file reports and a fail-closed INCOMPLETE verdict.
- **Booto could learn:**
  - Flash-content scanning with a GUID/hash/regex blocklist.
  - TSEG lock checks and the SPI descriptor and flash lock (FLOCKDN) checks.
  - The ME manufacturing-mode check.
  - Its JSON results with delta comparison (`--deltas`).

## fwupd HSI (`fwupdmgr security`)
- **What it is:** fwupd's Host Security ID, which scores a machine HSI:0–5 from firmware-protection attributes and adds a runtime `!` suffix (Secure Boot off, tainted kernel, no lockdown, unencrypted swap). https://fwupd.github.io/libfwupdplugin/hsi.html
- **Mode:** live daemon on the running OS. It reads sysfs, MSRs, MEI and efivars. [INFERENCE] It could run from the same Debian live USB as Booto.
- **Detection:** about 45 `org.fwupd.hsi.*` attribute IDs, listed from `libfwupd` at main (cloned 2026-11-03); see the HSI table below.
- **dbx handling (`uefi-dbx` plugin):**
  - Before applying a dbx update it computes Authenticode hashes of first- and second-stage ESP binaries and refuses the update if any of them would be blocked. https://github.com/fwupd/fwupd/blob/main/plugins/uefi-dbx/fu-uefi-dbx-common.c
  - It versions dbx by its *last-entry checksum* because Microsoft sometimes removes hashes, so the count alone is unreliable. https://github.com/fwupd/fwupd/blob/main/plugins/uefi-dbx/README.md
  - The DBXUpdate payloads are mirrored in https://github.com/fwupd/dbx-firmware.
  - The README says dbx state is "stored in a security attribute for HSI", but I found no `Uefi.Dbx` ID in `libfwupd`; it is exposed as a device version instead.
- **Maintenance/licence:** 2.1.9 released 2026-10-23 (it fixed handling of a missing or 2023-only dbx); last push 2026-11-02; LGPL-2.1. https://github.com/fwupd/fwupd/releases/tag/2.1.9
- **Booto does better:**
  - Hunts for actual implants on disk; HSI only grades posture.
  - Checks Intel SMRAMC D_LCK and SMRR, which have no HSI attribute.
  - Checks for test keys in KEK and db as well as PK.
  - Reports Setup Mode separately.
- **Booto could learn:**
  - dbx *freshness* (last-entry checksum against the latest known list), instead of only checking that dbx is non-empty.
  - The ESP-binary-in-dbx cross-check.
  - Whether db holds the 2023 Microsoft CAs (`Uefi.Db`).
  - The BIOSWE, SPI descriptor, ME, BootGuard and TPM PCR attributes.

## UEFITool / UEFIExtract / UEFIFind
- **What it is:** a parser and viewer for UEFI PI firmware images (FFSv2/v3 volumes, files, sections), with an integrity check.
  - UEFIExtract dumps the parsed tree to the filesystem.
  - UEFIFind searches image elements for a pattern.
  - https://github.com/LongSoft/UEFITool/blob/new_engine/README.md
- **Mode:** offline, on a firmware image file. It does not read SPI flash itself.
- **Detection:** none by itself. It is a structure parser that analysts or other tools (e.g. UBU) build on.
- **Maintenance/licence:** NE A76 released 2026-10-24; last push 2026-10-27; BSD-2-Clause. The C++ `ffsParser` could legally be ported or studied. https://github.com/LongSoft/UEFITool/releases/tag/A76
- **Booto does better:** it has detection logic and verdicts, and covers the disk and the OS boot chain.
- **Booto could learn:**
  - If Booto ever takes SPI dumps (e.g. made with `flashrom` [INFERENCE]), the UEFIExtract CLI could be shipped on the ISO as an optional external parser rather than reimplementing FFS.
  - The FFS tree is also the substrate that FwHunt and CHIPSEC blocklists match against.

## ESET UEFI Scanner
- **What it is:** a module in ESET's Windows endpoint and server products, run as part of HIPS. It scans the firmware for malicious components. https://help.eset.com/glossary/en-US/technology_uefi.html , https://web-assets.eset.com/fileadmin/ESET/INT/Docs/Others/Technology/ESET-Technology.pdf (p.7)
- **Mode:**
  - Live agent: scans at startup, or on demand with the "Boot sectors/UEFI" scan target.
  - The product list in KB6567 is Windows only: Endpoint 8.1+, Server Security 8+, NOD32/Internet Security 17+.
  - It cannot remove a detection; the advice is a vendor update or reflashing the SPI flash. https://support.eset.com/en/kb6567-you-receive-an-eset-uefi-detection (updated 2026-10-23)
- **Detection:** proprietary signatures and DNA detections on firmware content (e.g. `EFI/CompuTrace`, `EFI/Lenovo`). Its track record includes LoJax, ESPecter, BlackLotus and Bootkitty (see the research section below).
- **Maintenance/licence:** commercial and closed; the KB is current as of 2026-10.
- **Booto does better:**
  - Linux targets, read-only offline acquisition, and open, sealed rules.
  - Analysts can see why a detection fired.
- **Booto could learn:**
  - Treat ESP binaries as malware targets, not only as dbx hashes.
  - Give per-family names and remediation text (e.g. "restore `grubx64-real.efi`" for Bootkitty).

## Microsoft Defender UEFI scanner
- **What it is:** a component of Defender Antivirus on Windows 10+ and Server 2019+. It requires real-time protection and behaviour monitoring to be on. https://learn.microsoft.com/en-us/defender-endpoint/uefi-scanning-in-defender-for-endpoint (updated 2026-08-14)
- **Mode:** live. It reads SPI flash "by interacting with the motherboard chipset". Scans are triggered by runtime events (e.g. suspicious driver load) and by periodic scans, and results go to the Defender portal. https://www.microsoft.com/en-us/security/blog/2020/06/17/uefi-scanner-brings-microsoft-defender-atp-protection-to-a-new-level/
- **Detection:**
  - "UEFI anti-rootkit" for SPI access, a full firmware-filesystem scanner, and a detection engine for exploits and malicious behaviour.
  - Anomaly signals are sent to the cloud.
  - For BlackLotus it uses hash signatures plus the alert "Possible vulnerable EFI bootloader". https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
- **Maintenance/licence:** commercial and closed; maintained by Microsoft.
- **Booto does better:** runs offline and cannot be blinded by a running bootkit; BlackLotus disables Defender (same MS blog).
- **Booto could learn:**
  - A "vulnerable (revoked) bootloader present on the ESP" alert.
  - Analysing MeasuredBoot/TCG logs, i.e. diffing boot apps in PCR4 `EV_EFI_BOOT_SERVICES_APPLICATION` events between boots (same MS blog).

## Eclypsium (commercial)
- **What it is:** a cloud firmware and supply-chain security platform covering endpoints, servers, network gear, BMCs, ME, TPM and option ROMs. https://eclypsium.com/platform/specs/ (modified 2025-11-14)
- **Mode:** agent, managed from the cloud or on-prem. Supports Windows, macOS and Linux (Ubuntu 16.04–22.04, Debian 11, RHEL 7–9). https://eclypsium.com/wp-content/uploads/Eclypsium-for-Endpoints.pdf
- **Detection** (same two sources):
  - An allowlist of "over 12 million known good firmware hashes".
  - Baseline drift detection.
  - Known-threat detection with customer-imported YARA rules.
  - Checks for misconfiguration (BIOS WP, SMI and flash-descriptor locks), out-of-date firmware and CVEs.
- **Maintenance/licence:** commercial, active.
- **Booto does better:**
  - Free and offline, with no agent to subvert.
  - Disk-level bootkit and rootkit engines (LKM, initramfs, LD_PRELOAD).
- **Booto could learn:**
  - Allowlisting known-good hashes beats blocklisting for boot binaries. A small known-good set (distro shim and GRUB Authenticode hashes) would flag *unknown* bootloaders.
  - YARA-style user rules.

## Binarly efiXplorer & FwHunt
- **efiXplorer:**
  - An IDA plugin and loader that recovers UEFI protocols, GUIDs and service calls and flags SMM-callout-type bugs (BH EU 2020 paper linked in the README). https://github.com/REhints/efiXplorer
  - Repo now at REhints; v6.3.0 released 2026-08-20; GPL-3.0.
  - Analyst tooling, not a scanner.
- **FwHunt rules:**
  - YAML rules (CC0-1.0) with `hex_strings` (with `..` wildcards), `guids`, `protocols`, `nvram`, `code` and `strings` conditions. https://github.com/binarly-io/FwHunt
  - 108 rules across Threats, Vulnerabilities, SupplyChain and MitigationFailures.
  - The Threats folder has BlackLotusBootkit (target: bootloader), ESPecter, Rkloader, Lojax-SecDxe, MoonBounce-CORE-DXE, MosaicRegressor and CosmicStrand.
  - **Stale:** last commit 2024-03-12.
- **fwhunt-scan:** the rule scanner. GPL-3.0, Python plus rizin; last commit 2025-05-02. https://github.com/binarly-io/fwhunt-scan
- **PKfail:** Binarly disclosed it on 2024-07-25 (test/AMI "DO NOT TRUST" PKs across hundreds of models) and runs a free upload API at https://pk.fail/. https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot
- **Booto does better:** an integrated offline workflow, and PKfail checked live from efivars (PK+KEK+db) with no upload.
- **Booto could learn:**
  - **The CC0 rules can be copied into MIT Booto.** The BlackLotus, ESPecter and Rkloader hex strings fit Booto's byte-pattern engine if it supports wildcards.
  - Binarly's PKfail data includes specific leaked certificates (serial/issuer), which would be more precise than CN substring markers alone.

## sbctl & mokutil (Secure Boot state)
- **sbctl:**
  - A Go tool for managing your own Secure Boot keys. https://github.com/Foxboron/sbctl/blob/master/docs/sbctl.8.txt
  - `status` shows Secure Boot, Setup Mode and owner GUID.
  - `verify` walks PE files on the ESP and checks they are signed by the user's db key.
  - `list-enrolled-keys`; JSON output with `-j`.
  - v0.18 released 2025-10-07; last push 2026-09-06; MIT. Issue #22 discusses importing uefi.org dbx files. https://github.com/Foxboron/sbctl/issues/22
- **mokutil:**
  - Manages shim Machine Owner Keys: `--sb-state`, `--pk/--kek/--db/--dbx` listing, `--list-enrolled`/`--mokx`, `--list-sbat-revocations`, `--set-sbat-policy`, `--test-key`/`--ca-check`. https://github.com/lcp/mokutil/blob/master/man/mokutil.1
  - v0.7.2 released 2024-03-19; last commit 2026-09-03; GPL-3.0.
- **Mode:** both run live on the running OS and read efivars.
- **Booto does better:** offline forensic context; PKfail and dbx assessment; reports.
- **Booto could learn:**
  - **MOK audit.** BlackLotus persists by writing its own key to `MokList` (ESET, below). The kernel exposes the shim MOK config table read-only at `/sys/firmware/efi/mok-variables/` (https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/mokvar-table.c), so Booto can list enrolled MOKs and flag self-signed or unknown ones.
  - **SBAT.** Read `SbatLevel` and compare it with the `.sbat` sections of ESP shim and GRUB. Linux bootloader revocation moved from dbx to SBAT generations. https://github.com/rhboot/shim/blob/main/SBAT.md (shim 16.1, 2025-08-13)
  - **Signer check.** sbctl's `verify` shows the value of checking ESP PE signers.

## The real UEFI dbx and how tools consume it
- **Sources:**
  - Official files are on uefi.org (https://uefi.org/revocationlistfile, archive at https://uefi.org/revocationlistfile/archive). The site returned HTTP 403 to scripted fetch, so I did not verify the page contents.
  - The canonical, machine-readable source is **microsoft/secureboot_objects**: v1.7.1 released 2026-10-20, last commit 2026-10-28, licence BSD-2-Clause-Patent (MIT-compatible). https://github.com/microsoft/secureboot_objects
- **`PreSignedObjects/DBX/dbx_info_msft_latest.json`:**
  - **Authenticode SHA-256 entries:** x64 445, ia32 96, aarch64 26, arm 110, giving 676 unique hashes. Each entry has filename, signer and date; the newest x64 entry is dated 2026-07-07.
  - **1 certificate:** "Microsoft Windows Production PCA 2011", added 2024-02-01 for CVE-2023-24932.
  - **3 SVN entries:** bootmgfw SVN 12.0 (CVE-2026-45654, 2026-09-10), cdboot 3.0 and wdsmgfw 3.0.
- **Signed payloads:**
  - Now under `PostSignedObjects/SignedByKEK2023/*.efiauth2` and `SignedByKEK2011/*_Legacy`.
  - The old `PostSignedObjects/DBX/` folder is deprecated (KEK 2011 has expired) and "will be deleted in 2027" (folder README).
- **BlackLotus mitigation (CVE-2023-24932):** KB5025885 adds the PCA 2011 cert to dbx and applies a firmware SVN. Enforcement phase "date to be announced". https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
- **Consumers:**
  - fwupd ships DBXUpdate via LVFS and `fwupd/dbx-firmware`, versions it by last-entry checksum, and refuses updates that would block ESP binaries.
  - CHIPSEC has its own blocklist JSON.
  - Linux shim and GRUB revocation uses SBAT instead (above).
- **Finding against Booto's `rules/uefi_dbx_revocations.json`:**
  - None of its 5 SHA-256 values appear in Microsoft's 676.
  - `80b4d969…2408ca44b839…` shares its first 47 hex characters with Microsoft's 2018 `shim.efi` entry (`…2408ca8604d4…92659f0a`), then diverges. Booto labels it "BlackLotus Batched EFI Payload".
  - [INFERENCE] Two entries (`a849201b…`, `5f8a3562…`) contain sequential `0123ef` runs and look synthetic.
  - "MoonBounce Stage-2 Bootloader" is labelled as an ESP artefact, but MoonBounce is a SPI-flash CORE_DXE implant (FwHunt rule `MoonBounce-CORE-DXE`).
  - **These rules should be treated as unverified.**

## Detection research: Bootkitty (2024) and BlackLotus (CVE-2022-21894 / CVE-2023-24932)
- **Bootkitty** (ESET, 2024-11-27; later attributed to a Korean BoB student project; PoC, not seen in the wild). https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/ ; IoCs (SHA-1) at https://github.com/eset/malware-ioc/tree/master/bootkitty
  - **Signing and chain:** self-signed. It installs as `/EFI/ubuntu/grubx64.efi` and chain-loads the real GRUB, which it renames `/EFI/ubuntu/grubx64-real.efi`.
  - **Hooks:** UEFI Security/Security2 FileAuthentication, then `grub_verifiers_open`, `shim_lock_verifier_init`, and the kernel decompressor.
  - **Kernel patches:** makes `module_sig_check` return 0, rewrites the banner to "BoB13", and injects `LD_PRELOAD=/opt/injector.so /init` into init's environment.
  - **Companion module:** BCDropper LKM ("BlackCat" string in modinfo) drops `/opt/observer`, which loads `/opt/rootkit_loader.ko`.
  - **Offline-detectable by Booto:**
    - extra `grubx64-real.efi` next to `grubx64.efi`;
    - a self-signed second stage;
    - the `/opt/injector.so`, `/opt/observer` and `/opt/rootkit_loader.ko` paths;
    - "blackcat" or "BoB13" strings in LKMs.
- **BlackLotus** (ESET, 2023-03-01). https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/ ; Microsoft IR guide: https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
  - **Chain:** brings its own vulnerable, signed `bootmgfw.efi` and `hvloader.efi` and stages them in a custom `ESP:\system32\` directory, which stays behind after install.
  - **Persistence:** exploits Baton Drop, then writes the attacker's key into `MokList` and runs a self-signed `grubx64.efi` behind a Microsoft-signed shim placed at `\EFI\Microsoft\Boot\bootmgfw.efi`.
  - **Offline-detectable by Booto:**
    - a shim and `grubx64.efi` under `\EFI\Microsoft\Boot\` (an anomaly on Windows ESPs);
    - the `ESP:\system32\` directory;
    - revoked or vulnerable boot manager hashes (Microsoft dbx JSON);
    - an unknown MOK enrolled.

## HSI vs Booto check table
Legend: ✅ equivalent · ◐ partial · ❌ missing · ➕ Booto-only · n/a not meaningful for an offline live-USB scanner.
HSI level is the "needed to meet" level from https://fwupd.github.io/libfwupdplugin/hsi.html.

| HSI attribute (level) | What it checks | Booto equivalent | Status |
|---|---|---|---|
| Uefi.SecureBoot (1) | SecureBoot enabled | "Secure Boot on" | ✅ |
| — | SetupMode = 0 | "Setup mode off" | ➕ |
| Uefi.Pk (1) | PK is not a test key ("DO NOT TRUST - AMI Test PK") | "Platform key" + "No test keys (PKfail)", which scans PK, KEK and db for DO NOT TRUST/SHIP | ✅ (Booto broader) |
| Uefi.Db (MsUefi/Production) | db holds Microsoft UEFI CA 2023 | — | ❌ |
| uefi-dbx plugin (device version, not an HSI ID) | dbx up to date (last-entry checksum vs LVFS); ESP binaries not blocked | "Revocation list (dbx)": non-empty count only | ◐ |
| Uefi.BootserviceVars (1) | Boot-service vars not readable at runtime | — | ❌ |
| Uefi.MemoryProtection / NxCompat (3) | NX bootloader + firmware memory attributes | — | ❌ |
| Spi.Bioswe (1) | BIOS_CNTL.BIOSWE clear | Not read (only BLE/SMM_BWP) | ❌ |
| Spi.Ble (1) | BIOS_CNTL.BLE set | "BIOS write protection" | ✅ (Intel) |
| Spi.SmmBwp (1) | BIOS_CNTL.SMM_BWP set | "BIOS write protection" (also flags pre-5-series chipsets with no SMM_BWP; CVE-2014-8273) | ✅ (Intel) |
| Spi.Descriptor (1) | Flash descriptor read-only | — | ❌ |
| — (CHIPSEC `smm`) | Intel SMRAMC D_LCK | "SMM locked" | ➕ |
| — (CHIPSEC `smrr`) | Intel SMRR valid | "SMRAM range protected" | ➕ |
| Amd.SmmLocked (1) | HWCR.SmmLock + Sinkclose | "SMM locked" (HWCR.SmmLock); no Sinkclose check | ◐ |
| — (CHIPSEC `smm_dma`-like) | AMD TSEG valid (SMM_MASK.TValid) | "SMRAM range protected" | ➕ |
| Amd.SpiWriteProtection (2) / SpiReplayProtection (3) / RollbackProtection (4) / PlatformSecureBoot (2) / EntrySign (1) | PSP-reported AMD protections | AMD BIOS WP reported N/A ("needs MMIO") | ❌ |
| Iommu (2) | IOMMU present **and enabled** | "IOMMU described (DMAR/IVRS)": table present only | ◐ |
| PrebootDma (3) | DMAR opt-in / IVRS pre-boot DMA | DMAR opt-in flag shown in detail text (Intel); not a pass/fail | ◐ |
| — | Thunderbolt `iommu_dma_protection` | "Thunderbolt DMA protection" | ➕ |
| IntelBootguard.{Enabled,Verified,Acm,Policy,Otp} (2–3) | BootGuard fuses/policy via MEI | — | ❌ |
| Mei.ManufacturingMode / OverrideStrap / KeyManifest / Version (1) | CSME state from HFSTS | — | ❌ |
| PlatformDebugEnabled (DCI) (1) / DebugLocked (2) / PlatformFused (1) | Debug interfaces locked | — | ❌ |
| Tpm.Version20 / EmptyPcr (1) / ReconstructionPcr0 (2) | TPM 2.0, PCRs populated, event log consistent | — | ❌ |
| SupportedCpu (1) | Platform has HSI tests | `chipset_unconfirmed` flag | ◐ |
| SuspendToRam / SuspendToIdle (3) | S3 disabled | — | ❌ (low value) |
| EncryptedRam (4), Smap (4), Cet.* (3), IntelGds (2) | CPU hardening features | — | ❌ (low forensic value) |
| Bios.CapsuleUpdates (1), Bios.RollbackProtection (2), Hp.Surestart (2) | OEM firmware features | — | ❌ |
| Kernel.Lockdown / Kernel.Tainted / Kernel.Swap (runtime `!`) | State of the booted OS | Would measure the live USB kernel, not the suspect OS | n/a |
| Fwupd.* (Attestation/Plugins/Updates) | fwupd self-state | — | n/a |

## Top ideas for Booto (ranked by value ÷ effort)
1. **Generate the DBX rules from `microsoft/secureboot_objects`.**
   - Build them from `dbx_info_msft_latest.json`, which is BSD-2-Clause-Patent.
   - Flag ESP binaries whose Authenticode hash is Microsoft-revoked but **missing from the host's dbx**. That is the BlackLotus "bring your own vulnerable bootloader" case.
   - Rationale: low effort, since the data is already JSON. It also replaces the current 5 unverifiable hashes.
2. **ESP boot-chain anomaly checks.**
   - Extract each PE's Authenticode signer and flag self-signed or unknown second stages.
   - Flag `grubx64-real.efi`-style shadow copies, the `ESP:\system32\` directory, and shim plus `grubx64.efi` under `\EFI\Microsoft\Boot\`.
   - Rationale: these catch both public Linux and Windows bootkits structurally, without per-sample hashes.
3. **MOK + SBAT audit.**
   - List the certificates in `/sys/firmware/efi/mok-variables/MokListRT` (and MokListX) and flag self-signed or non-vendor MOKs.
   - Read `SbatLevel` and compare it with the `.sbat` sections of ESP shim and GRUB.
   - Rationale: covers BlackLotus-style MOK persistence and Linux's real revocation path at low cost, reading sysfs and efivars as Booto already does.
4. **Import the CC0 FwHunt Threat rules** (BlackLotusBootkit, ESPecter, Rkloader) into the byte-pattern engine, adding `..` wildcard support if it is missing.
   - Rationale: free, licence-compatible family signatures for ESP binaries.
5. **Close the cheap HSI-1 gaps.**
   - Add BIOSWE (bit 0 of the BIOS_CNTL byte Booto already reads).
   - Add db 2023-CA presence and dbx freshness (count plus last-entry checksum against the Microsoft JSON).
   - Read ME manufacturing mode and override strap from the HFSTS registers in MEI PCI config space.
   - Rationale: these match the baseline fwupd users expect, each using a data source Booto already opens. The MEI register reads are [INFERENCE] and need checking against the fwupd `intel-me` plugin.

---

# Live / boot-from-USB forensic environments vs Booto

Researched 2026-11-03. Dates and licences come from vendor pages or the GitHub API (`releases/latest` and `repos/<r>`). Anything marked `[INFERENCE]` is my own reasoning and is not stated in a source.

## Kaspersky Rescue Disk (KRD 24)
- **What:** a free bootable Linux image. It runs *Kaspersky Rescue Tool* to disinfect a computer without booting its OS. It "scans only Windows computers" ([about](https://support.kaspersky.com/krd/24/269439), [scan](https://support.kaspersky.com/krd/24/269444)).
- **Mode:** offline boot, but "Kaspersky Rescue Tool needs an internet connection to work" for KSN cloud reputation and database updates. The cloud link also sends detected objects to Kaspersky ([internet](https://support.kaspersky.com/krd/24/272922)).
- **Detection:** AV databases plus KSN. It scans memory, startup objects, **boot sectors** and all files, including archives ([scan](https://support.kaspersky.com/krd/24/269444)).
- **Evidence handling:** none. Its purpose is disinfection and quarantine ([help index](https://support.kaspersky.com/krd/24)), and updated databases are saved *to the suspect's hard drive* ([update](https://support.kaspersky.com/krd/24/270048)).
- **Reports:** the standard report is an encrypted `report_<date>_*.klr.enc1`; an optional detailed `.klr` needs the `fullreport` boot option ([reports](https://support.kaspersky.com/krd/24/270026)).
- **Signature updates:** download a new ISO ("continuously updates the image file"), or use an online "Update now" button ([update](https://support.kaspersky.com/krd/24/270048)). There is no offline update package.
- **Maintenance and licence:** KRD 24 docs are dated 2024-11-25; the ISO is at `rescuedisk.s.kaspersky-labs.com/updatable/2024/krd.iso`. Proprietary freeware.
- **Booto does better:** it is truly offline, never writes to the target, and covers Linux targets. It has no telemetry, its reports are plain JSON/MD, and its verdict model is CLEAN/THREATS/INCOMPLETE.
- **Booto could learn:** detection data ships *inside the ISO* and the ISO is rebuilt continuously. Booto's CI ISO build could do the same for its sealed rules, which closes the "no network update" gap without adding networking.

## ESET SysRescue Live
- **What:** a Linux-based malware-cleaning boot disk built on ESET's UNIX scanner. It downloaded signature updates when the network was up ([ESET forum, 1.0.9.0 announcement](https://forum.eset.com/topic/2372-eset-sysrescue-live-1090-released)).
- **Status:** **EOL 2023-09-29**. It is no longer available for download, and existing copies have outdated threat databases ([ESET EOL](https://support-eol.eset.com/en/sysrescue_live_eol.html)). ESET's replacement, Online Scanner, is a Windows tool that runs inside the running OS, so it is not a rescue disk (same source). Proprietary.
- **Booto does better:** it is still alive, and its rules ship sealed with the ISO.
- **Booto could learn:** this is market evidence, not a technique. Vendor AV rescue disks are being dropped (see Trend Micro below), so the offline boot-scanner niche is open, especially for Linux targets.

## Trend Micro Rescue Disk
- **What:** a boot-time scanner for "hidden files, system drivers, and the MBR". It does not load the potentially infected OS. It supported NTFS/FAT and **ext2/3/4 and XFS** ([Portable Security 3 docs](https://docs.trendmicro.com/en-us/documentation/article/trend-micro-portable-security-3-trend-micro-rescue-d)).
- **Evidence handling:** by default it **quarantines to the local hard drive**. Read-only operation needs the "Scan only" action to be set manually (same doc).
- **Status:** **discontinued 2025-04-25**. There are no downloads and no updates ([Trend help center](https://helpcenter.trendlife.com/en-us/article/tmka-12905)). Proprietary.
- **Booto does better:** read-only is the default and is enforced (BLKROSET plus no-replay mount options), and the project is alive.
- **Booto could learn:** it scanned the MBR and covered XFS, so Booto's filesystem coverage beyond ext4 is a real need.

## Tsurugi Linux (LAB 26.03 / Tsurugi Acquire)
- **What:** an Ubuntu-based DFIR/OSINT distribution. Its "Write Blocker system has been enforced at kernel level", and automount, autorun and hibernation settings are reset to safe defaults every session ([features](https://tsurugi-linux.org/documentation_tsurugi_linux_special_features.php)).
- **Mode:** live, or installed. Tsurugi Acquire is a live-only acquisition image, but it is based on Debian 10 with a 32-bit 5.11.6 kernel ([Acquire](https://tsurugi-linux.org/documentation_tsurugi_acquire.php)). `[INFERENCE]` That base is stale.
- **Detection:** no engine of its own. It is a toolbox that bundles YARA, ClamAV, Velociraptor, Volatility, LiME, TSK, Autopsy and others ([changelog](https://tsurugi-linux.org/documentation_tsurugi_linux_changelog.php)).
- **Maintenance:** release 26.03 shipped 2026-04-04 with kernel 6.19.10; 25.11 (Nov 2025) was a rebuild on Ubuntu 24.04.3 ([changelog](https://tsurugi-linux.org/documentation_tsurugi_linux_changelog.php)). GPL ([downloads](https://tsurugi-linux.org/downloads.php)).
- **Booto does better:** it gives a single automated verdict, has bootkit, UEFI and firmware engines, and produces a case report instead of leaving the analyst to drive tools by hand.
- **Booto could learn:** write-blocking is *global and at boot*, not per mount. Its ClamAV and YARA bundle shows that users expect generic signature scanning alongside the specialist checks.

## CAINE 14.0 "Lightstream"
- **What:** an Italian forensic live distribution on Ubuntu 24.04 with kernel 6.8. **All block devices are set read-only (`blockdev`) by default**; a GUI "UnBlock" tool and the "Mounter" tray tool switch the policy ([home/changelog](https://www.caine-live.net/)).
- **Evidence handling:**
  - `rbfstab` writes read-only fstab entries for every plugged device.
  - A "Save as Evidence" script copies files and writes a metadata report with an investigator comment.
  - A **Casper patch stops the live initramfs from booting a fake root filesystem planted on the evidence media** ([home](https://www.caine-live.net/)).
- **Reports:** a report-creation tool existed only up to CAINE 4.0 ([report page](https://www.caine-live.net/page12/page12.html)).
- **Maintenance and licence:** 14.0 was released 2025-03-24. CAINE is LGPL; the Windows-side tools are freeware ([home](https://www.caine-live.net/)).
- **Booto does better:** it has automated detection and integrated report generation and sealing.
- **Booto could learn:**
  1. Set every block device read-only at boot, not only the partition being mounted.
  2. Defend against a **planted `/live` root on the suspect disk**. Booto's GRUB uses `search --file /live/vmlinuz` and live-boot then scans all disks (`scripts/build_iso.sh:103-113`). See Top idea 1.

## PALADIN 9 LTS (SUMURI)
- **What:** an Ubuntu 24.04 forensic live suite. In forensic mode the OS is "modified to prevent changes to attached media, disable auto-mounting from the moment you boot" ([product](https://sumuri.com/paladin/), [9 LTS notes](https://sumuri.com/updates/paladin-9-lts/)).
- **Evidence handling:**
  - The PALADIN Toolbox GUI does imaging, logical acquisition and hashing, with "read-only access options and logging built in".
  - It bundles dc3dd, Guymager and libewf (E01), plus QuickHash, hashdeep and ssdeep.
  - It bundles Volatility 3 ([9 LTS notes](https://sumuri.com/updates/paladin-9-lts/)).
- **Detection:** no rootkit engine. It is imaging plus triage tools.
- **Maintenance:** current release **9.4.2**, with a Linux 6.17 kernel ([updates](https://sumuri.com/updates/), [notes](https://sumuri.com/updates/paladin-9-lts/)). `[INFERENCE]` The banner path suggests June 2026. It boots with Secure Boot on ([product](https://sumuri.com/paladin/)).
- **Licence:** proprietary EULA, name-your-price. Corporate users pay at least $25 ([product](https://sumuri.com/paladin/), [EULA](https://sumuri.com/paladin-eula/)).
- **Booto does better:** open GPL-3.0 code, automated rootkit, bootkit and firmware verdicts, and no licence gate.
- **Booto could learn:** it has separate forensic and non-forensic boot entries, signed-shim Secure Boot support, and it tells users to verify the ISO hash before use.

## Kali Linux forensic mode
- **What:** a live-boot entry inherited from BackTrack. The internal disk is never touched, swap is not used, and automount is disabled ([Kali docs](https://www.kali.org/docs/general-use/kali-linux-forensics-mode/)).
- **How:** only through kernel cmdline. GRUB passes `noswap noautomount`; syslinux passes `systemd.swap=no noautomount` ([kali-live grub.cfg](https://gitlab.com/kalilinux/build-scripts/kali-live/-/raw/main/kali-config/common/bootloaders/grub-pc/grub.cfg), [live.cfg.in](https://gitlab.com/kalilinux/build-scripts/kali-live/-/raw/main/kali-config/common/bootloaders/syslinux_common/live.cfg.in)). It does not block-level setro.
- **Validation:** Kali hashed a drive, booted forensic mode, used it, then re-hashed the drive; the hashes matched. It tells users to validate the tools themselves ([Kali docs](https://www.kali.org/docs/general-use/kali-linux-forensics-mode/)).
- **Maintenance:** quarterly releases; 2026.3 shipped 2026-10-26 ([blog](https://www.kali.org/blog/kali-linux-2026-3-release)). Licence is per package `[INFERENCE]`.
- **Booto does better:** the block-level BLKROSET plus no-replay mounts are stronger than boot flags alone, and it adds detection.
- **Booto could learn:** add an explicit `systemd.swap=no` to the cmdline. Booto's GRUB lines have none (`scripts/build_iso.sh:107,113`). `[INFERENCE]` systemd-gpt-auto-generator can otherwise activate swap. Also publish a before/after hash validation as a reproducible test.

## Velociraptor (offline collector)
- **What:** a VQL endpoint engine. An *offline collector* is the standard binary with the artifacts and tools embedded. **"Offline" means without the server, not dead disk:** the endpoint OS must be running ([offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)). Dead-disk use goes through accessor remapping and host impersonation, is mainly automated for Windows images, and disables plugins that read non-disk data ([deaddisk](https://docs.velociraptor.app/docs/forensic/deaddisk/)).
- **Detection:** artifacts written in VQL, plus a `yara()` plugin built on libyara 4.5.4 with the pe, elf, math, time and dotnet modules. It has no OpenSSL, so `pe.signatures` is always empty ([yara](https://docs.velociraptor.app/vql_reference/parsers/yara/)).
- **Evidence handling:**
  - Output is a ZIP container with `results/*.json`, `log.json`, `collection_context.json` and per-file `SourceFileSha256` with timestamps.
  - The log records the container SHA-256 ([collection data](https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/)).
  - X.509 encryption uses a random key wrapped with the server certificate, and the ZIP is double-wrapped so file names do not leak ([offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)).
- **Updates:** updating artifacts means rebuilding the collector (same source).
- **Maintenance:** v0.77.3 shipped 2026-10-05; last push 2026-11-02 ([repo](https://github.com/Velocidex/velociraptor)). **AGPL-3.0** (LICENSE file), so its code cannot be copied into MIT Booto.
- **Booto does better:** it does true dead-box scanning of a Linux disk and has boot, UEFI and firmware engines that Velociraptor lacks.
- **Booto could learn:**
  - Record a hash of the report container in the log.
  - Use JSON results with a per-artifact `_Source`.
  - Give each finding its source file hash and timestamps.

## Volatility 3 + LiME / AVML (the memory-forensics gap)
- **Volatility 3:** it analyses memory images. The Linux plugins include `check_syscall`, `check_modules`, `hidden_modules`, `check_idt`, `check_afinfo`, `tty_check`, `modxview`, `malfind`, `netfilter`, `ebpf`, and `tracing/ftrace` and `tracepoints` ([plugin tree](https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins/linux)). The renderers include `json`, `jsonl` and `csv` ([text_renderer.py](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/cli/text_renderer.py)).
- **Volatility 3 limitation:** a Linux analysis needs an ISF symbol table whose banner matches the image **exactly**, built with dwarf2json from the debug kernel; that "may not be possible" ([symbol tables](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)).
- **Volatility 3 maintenance and licence:** v2.28.2 shipped 2026-09-17 ([releases](https://github.com/volatilityfoundation/volatility3/releases)). Volatility Software License 1.0, which is not MIT ([LICENSE.txt](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt)).
- **LiME:** a loadable kernel module that must run on the *live* suspect kernel. Formats are raw, padded and lime; an optional `digest=` writes a sidecar hash file such as `ram.lime.sha256`. It can output over TCP. v1.12.0 shipped 2026-03-31. The repo has moved to [jtsylve/LiME](https://github.com/jtsylve/LiME). **GPL-2.0.**
- **AVML:** Microsoft's userland memory acquirer. MIT licence; v0.21.0 shipped 2026-10-09 ([repo](https://github.com/microsoft/avml)). UAC ships an `avml.yaml` artifact ([UAC](https://github.com/tclahr/uac)).
- **Booto does better:** none of these tools can say anything about a powered-off disk, the boot chain or firmware locks.
- **Booto could learn:** Booto cold-boots, so RAM is gone by design. The low-cost fix is a documented *pre-shutdown capture* step with AVML (MIT, so it can be shipped on the stick). Booto could also optionally ingest `vol -r json` output from the `linux.malware.*` plugins into its verdict.

## GRR Rapid Response
- **What:** remote live forensics at scale. A client agent polls GRR/Fleetspeak servers, and a web UI plus REST API schedule actions. It offers raw filesystem access via TSK and **live remote memory scanning with YARA** ([what is GRR](https://raw.githubusercontent.com/google/grr-doc/master/what-is-grr.md)).
- **Mode:** agent only, on a running OS, with server infrastructure. There is no boot or offline mode.
- **Maintenance and licence:** v4.0.0.0 shipped 2025-12-15; last push 2026-10-01 ([repo](https://github.com/google/grr)). Apache-2.0 ([docs](https://grr-doc.readthedocs.io/en/latest/)).
- **Booto does better:** no infrastructure is needed, the target OS is never trusted, and it is air-gap friendly.
- **Booto could learn:** very little for a single-host offline tool. Its fleet-hunt model is out of scope. Its YARA-on-memory feature confirms that YARA is an expected baseline capability.

## UAC (Unix-like Artifacts Collector)
- **What:** a dependency-free shell collector driven by YAML artifacts and profiles. It runs on Linux, BSD, macOS, Solaris, AIX and ESXi ([README](https://github.com/tclahr/uac)).
- **Offline/dead-disk mode:** `./uac -p offline -m /mnt/sda1 DEST` ([docs](https://tclahr.github.io/uac-docs/)). The `offline` profile collects:
  - a bodyfile;
  - hashes of all files with the +x bit (`hash_executables`);
  - `chkrootkit -n -r <mount>` output;
  - `/etc/ld.so.preload` dumped via debugfs or xfs_db "even if it is hidden by LD_PRELOAD rootkits";
  - system, SSH, package and file artifacts ([offline.yaml](https://github.com/tclahr/uac/blob/main/profiles/offline.yaml), [chkrootkit artifacts](https://github.com/tclahr/uac/tree/main/artifacts/chkrootkit)).
- **Evidence handling:**
  - `--case-number`, `--evidence-number`, `--examiner`, `--description` and `--notes` flags.
  - `-H` hashes every collected file into a hash file.
  - An acquisition log sits beside the `tar.gz`/`zip` output (optionally password-protected), with optional SFTP/S3/Azure upload ([docs](https://tclahr.github.io/uac-docs/)).
- **Updates:** artifacts are plain YAML that users edit or add (`-a /my_custom_artifacts/*`). There are no signatures to update.
- **Maintenance and licence:** v3.4.0 shipped 2026-09-09; last push 2026-10-26 ([repo](https://github.com/tclahr/uac)). **Apache-2.0**, so its ideas and code can be reused in MIT Booto with attribution.
- **Booto does better:** it gives an actual verdict instead of raw collection, and has MBR, VBR, UEFI, firmware, initramfs and LKM ELF analysis that UAC delegates to chkrootkit or does not do at all.
- **Booto could learn:**
  - Proper case-metadata flags. Booto auto-generates the case ID and takes the examiner from `$USER` (`src/main.c:93-101`).
  - A bodyfile plus a hash list of executables as standard, interoperable outputs.

---

## Cross-cutting findings
- **Write-blocking:** the tools use three levels.
  - Boot flags only: Kali `noswap noautomount`.
  - OS policy: PALADIN, and Tsurugi's "kernel-level" blocker.
  - Every block device set read-only at boot: CAINE `blockdev`.

  Booto sets BLKROSET only on the device it mounts (`src/disk_mount.c:601-608`) and has no boot-time policy.
- **Boot-media spoofing:** only CAINE addresses an attacker planting a fake live root on the evidence disk. Booto is exposed at two layers: GRUB's `search --file /live/vmlinuz`, and live-boot's default scan of all block devices. Debian's live-boot supports `live-media=removable|removable-usb` and `verify-checksums` ([live-boot(7)](https://manpages.debian.org/trixie/live-boot-doc/live-boot.7.en.html)).
- **Chain of custody:**
  - UAC: case, evidence, examiner and notes flags, hashes of collected files, an acquisition log.
  - Velociraptor: per-file SHA-256 and a container hash in the log.
  - LiME: a digest sidecar.
  - Booto: seals the report file with SHA-256 (`src/case_reporter.c:76-99`), but records no evidence number, disk serial, or before/after integrity proof.
- **Signature updates offline:** the AV vendors either rebuild the ISO (Kaspersky) or needed the network (ESET, Trend), and two of the three are now dead. Toolbox distributions update only on distribution release. Velociraptor and UAC use user-edited artifacts. No tool here has a signed, offline rule-bundle import, so Booto's sealed JSON rules are already ahead. Signing them is the next step.

## Top ideas for Booto (ranked by value ÷ effort)
1. **Harden the live-boot cmdline:** use `search --fs-uuid`/`--label` in GRUB, and add `live-media=removable verify-checksums systemd.swap=no noautomount`. It is about a 3-line change in `scripts/build_iso.sh`, and it closes the planted-`/live` spoofing path that CAINE patched, plus a swap-write risk.
2. **Set every non-boot block device read-only at boot**, CAINE-style, with a udev rule running `blockdev --setro`. This goes beyond the per-mount BLKROSET. It is a few lines and turns "read-only by code path" into "read-only by default for everything", which is easier to defend in court.
3. **Chain-of-custody fields plus a before/after integrity proof:** add `--case-id/--examiner/--evidence-number/--notes` (UAC-style), record the disk model and serial, and hash LBA 0–2047, the GPT and the ESP at scan start and end. The report then carries Kali-style "no change" evidence. The effort is low because the hashing code already exists.
4. **Emit a bodyfile (mactime) and a SHA-256 list of executables** for the scanned root, as in UAC's offline profile. The outputs work with TSK timelines and known-good comparison, and they are groundwork for the planned hidden-file cross-view. The effort is medium.
5. **Cover the memory gap without building memory forensics:** document a pre-shutdown AVML capture (MIT, so it can be shipped on the USB) and optionally ingest Volatility 3 `-r json` output from the `linux.malware.*` plugins into the verdict. This addresses the main gap reviewers will raise, using existing tools without copying GPL code. The effort is low for the docs and medium for the ingest.
