# Booto FAQ: limits and review questions

Booto is beta software. Its detections have been tested on planted cases (`make zoo`) and a few clean installs, not on real bootkit samples. This page answers the questions reviewers ask most, including the limits that are not fixed yet.

## What does CLEAN mean?

No known threat was found in the disk parts Booto checked, and every engine that applies to the target ran. It is not proof that the machine is clean.

- Each engine reports `OK`, `ERROR`, `SKIPPED` or `N/A`.
- `SKIPPED` means the engine could have run but did not: you turned it off, there was no raw device (directory scan, so no MBR check), or the package database is one Booto cannot read (RPM). A skipped engine makes the verdict `INCOMPLETE`.
- `N/A` means the engine does not apply: the Windows engine on a Linux disk, the Linux engines on Windows, no initramfs, no EFI system partition. It does not change the verdict.
- `ERROR` makes the verdict `INCOMPLETE`.

## Does a CLEAN scan clear the firmware?

No. The firmware audit checks the machine Booto runs on, not the disk, and its result is printed separately ("not part of the verdict"). A disk can be clean while the SPI flash holds an implant (MoonBounce, CosmicStrand). `-x` dumps the flash read-only and walks it, but Booto has no known-good baseline for your board, so it can only flag hidden executables and known indicators.

## Does Booto verify Authenticode signatures?

Yes, for SHA-256 signatures: it checks the PKCS#7 signature, recomputes the PE image hash, compares it with the signed digest, and checks the signer against Microsoft's roots and the dbx. Known limits:

- **SHA-1 and SHA-384 signatures** are reported as not checked (`AUTHENTICODE_UNSUPPORTED`), never as valid. The Microsoft UEFI CA and Windows 10 and later drivers sign with SHA-256, so this mainly affects old Windows 7 era drivers.
- **Only the first certificate** in the PE certificate table is checked. Dual-signed files usually nest the second signature inside the first, so this rarely matters.
- **Timestamps and certificate revocation lists** are not checked; Booto runs offline. The dbx (revoked hashes) is checked.
- A valid signature does not mean a file is safe: signed but vulnerable loaders exist. The dbx and SBAT checks cover the publicly revoked ones.

## Are catalog-signed Windows drivers checked?

No. Many Windows drivers carry no embedded signature and are signed through a `.cat` file in `System32/CatRoot`. Booto does not read catalogs yet, so:

- An unsigned or third-party-signed **core** boot file (`winload`, `ntoskrnl.exe`, `hal.dll`, `ci.dll`) is a finding.
- Other unsigned or third-party-signed drivers are **counted** in the Windows engine note, not reported as findings, because they are usually catalog-signed and legitimate.

Catalog verification is planned; until then a malicious driver with no embedded signature that is not a boot-start driver can be missed.

## Is "Packed EFI Executable" proof of malware?

No. High entropy in an EFI code section is a hint, graded MEDIUM, because legitimate loaders can carry compressed data. HIGH and CRITICAL are kept for things a bootkit does: a dbx-revoked binary, an image changed after signing, a loader swapped or renamed.

## Does Booto write to the disk it scans?

It should not. Every mount uses `ro,nodev,noexec,nosuid` plus `noload` (ext4), `norecovery` (XFS) or `nologreplay` (Btrfs), and the block device is set read-only with `BLKROSET` first. The device stays read-only for the rest of the live session on purpose: nothing else in the session can write to it by mistake. Reboot to use the disk normally.

This is a software write block, not a hardware one. For evidence that must hold up in court, use a hardware write blocker as well.

## Can the USB installer wipe the wrong disk?

`scripts/setup_usb.sh` refuses a path that is not a whole disk, a disk that holds `/`, `/boot` or `/boot/efi`, and a non-removable disk unless you pass `--force-nonremovable`. It shows the model, size and serial, asks you to type the device path, and checks again right before wiping that the model, size and serial have not changed. `--yes` skips the typed confirmation, so use it only in scripts you have tested on a spare USB.

## Are the rules trustworthy?

The rule files are signed with Ed25519 and Booto refuses files that do not verify against the key built into the binary. A signature proves who published a rule, not that the rule is complete or free of false positives. The dbx list is generated from Microsoft's published file; the other rules are written by hand and tested in `tests/` and `tests/zoo/`.

## How was detection tested?

With planted cases built by `scripts/gen_mock_disk.sh` (`make zoo`): each case must trigger exactly its engine, and the clean cases must trigger nothing. These are synthetic. Real samples (BlackLotus, ESPecter, FinSpy, Diamorphine) still need testing in an isolated lab, and the results will be published per family. Until then, treat Booto's results as triage, not certification.
