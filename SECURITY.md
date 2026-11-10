# Security policy

## Reporting a vulnerability

Report it privately: open a [security advisory](https://github.com/Dellrall/Booto/security/advisories/new) on GitHub. Do not open a public issue for a vulnerability.

Include the Booto version (`booto -v`), what you did, and what happened. A disk image or file that triggers the problem helps most.

Only the latest release gets fixes.

## What counts

- A crash, memory error or code execution caused by a crafted disk, partition table, PE/ELF file, initramfs, package database, UEFI variable or rule file.
- Any write to a scan target. Booto must only read it.
- A way to make a tampered rule file or case report pass its check.
- A way for the sandboxed decompressors to reach the network or files outside their input.

## What Booto does not protect against

- **The machine's firmware lying.** Booto boots from USB, so the suspect disk's software is not running, but a compromised UEFI firmware or Intel ME still runs underneath Booto and can hide from it.
- **A tampered package database.** The package integrity check trusts the database on the target disk. An attacker who rewrites both a file and its recorded hash passes it.
- **An attacker with the USB.** Rule seals and report `.sha256` files are checksums, not signatures: someone who can write to the stick can change a file and its checksum.
- **Unknown bootkits.** Most engines match known patterns. A clean verdict means nothing known was found, not that the machine is clean.
- **Encrypted volumes it cannot open.** BitLocker volumes are not read. A LUKS volume is read only after you unlock it.
- **Releases are not signed.** The ISO ships with a SHA-256 checksum only; download it from the GitHub release page over HTTPS.
