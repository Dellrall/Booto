# Booto setup guide

How to put Booto on a USB stick, boot a suspect machine from it, scan the machine's disk and keep the reports.

## 1. Specification

### Machine being examined

| Item | Requirement |
| :--- | :--- |
| CPU | 64-bit x86 (amd64). ARM machines and Apple Silicon Macs cannot boot it. |
| Firmware | UEFI or legacy BIOS; the ISO boots in both modes. |
| Secure Boot | On or off. The stick boots through Debian's signed shim, GRUB and kernel, so machines with Microsoft's standard keys accept it. With Secure Boot on the kernel locks down `/dev/mem`, so the expert SPI flash dump (`-x`) needs Secure Boot off. A machine with only its owner's own keys refuses the stick: turn Secure Boot off for that boot. |
| RAM | 2 GiB minimum (the QEMU test VM uses 2048 MiB). The live system runs from RAM and never writes to the internal disks. |
| Boot source | Must allow booting from USB. The live system only loads from removable media (USB stick, CD/DVD). A USB SSD that reports itself as non-removable boots only via the "USB not detected" GRUB entry (finds this build's ISO by UUID). |
| Disk being scanned | Any disk Linux can mount read-only: ext4, xfs, btrfs, NTFS (Windows), LVM volumes, and LUKS (unlocked read-only from the TUI with `F3`, including LVM inside LUKS). The package check covers Debian-, Arch- and RPM-based systems; others show it as `SKIPPED`. A Windows disk gets the Windows boot chain check. BitLocker volumes are unlocked read-only with `F3` using their password or 48-digit recovery key; a locked one gives the verdict `INCOMPLETE`. |

### USB stick

| Item | Requirement |
| :--- | :--- |
| Size | 4 GB minimum: 3 GiB for the live system plus at least 64 MiB for reports. |
| Layout made by `setup_usb.sh` | Partition 1 `BOOTO_LIVE`: FAT32, 3 GiB, live system. Partition 2 `BOOTO_DATA`: ext4 for reports and rules, LUKS2-encrypted unless you choose no passphrase. |
| Report space | About 2 KiB per scan (JSON + Markdown reports plus their checksum files), so 64 MiB holds about 30,000 scans. Choose the size with `--data-size`; the default is the rest of the stick. |

### Computer used to prepare the stick

| Item | Requirement |
| :--- | :--- |
| OS | Debian 12 or newer, or Ubuntu 22.04 or newer (another Linux with the tools below also works). |
| Access | Root (`sudo`). |
| Network | Only for building the ISO yourself (it downloads Debian packages). Not needed if you download the release ISO. |

## 2. Requirements

Writing the USB stick (always needed):

```bash
sudo apt-get install -y gdisk dosfstools e2fsprogs cryptsetup util-linux udev parted
```

Building from source (optional, only to build the ISO yourself):

```bash
sudo apt-get install -y build-essential git libncurses-dev libblkid-dev libudev-dev \
    debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin grub-common mtools dosfstools
```

Testing the ISO in a virtual machine (optional):

```bash
sudo apt-get install -y qemu-system-x86 ovmf
```

## 3. Steps

### Step 1: Get the ISO

Option A, download the release (recommended):

1. Download `booto-<version>-amd64.iso` and `booto-<version>-amd64.iso.sha256` from <https://github.com/Dellrall/Booto/releases> (e.g. `booto-v1.9.4-beta-amd64.iso`; beta releases are marked pre-release, so `latest` may not show them).
2. Check the download: `sha256sum -c booto-<version>-amd64.iso.sha256`. It must print `OK`.
3. Optional, proves GitHub's CI built it from this repository (releases from v1.7.0 on): `gh attestation verify booto-<version>-amd64.iso --repo Dellrall/Booto`. It must print `Verification succeeded`.

Option B, build it yourself (about 10 minutes):

```bash
git clone https://github.com/Dellrall/Booto.git && cd Booto
sudo make iso          # writes dist/booto-live-amd64.iso
```

Optional check in a VM: `./scripts/run_qemu_vm.sh`.

### Step 2: Write the USB stick

Alternative on Windows or Linux without these scripts: [booto-writer](https://github.com/Dellrall/booto-writer) downloads, verifies and writes the ISO with the same layout.

Alternative with any raw writer (`dd`, caligula, balenaEtcher, Rufus in **DD mode**): write the ISO, boot it, and press `F4` to add the report partition in the free space ([Step 4](#create-unlock-change-or-remove-report-storage)). Needs an ISO from 1.9.4-beta on. Rufus's default ISO mode does not work: it fills the stick with one FAT partition and leaves no free space.

1. Plug in the stick and find its device name. The `TRAN` column must say `usb`:
   ```bash
   lsblk -d -o NAME,SIZE,MODEL,TRAN
   ```
2. Run the installer. **This erases the whole stick.** Replace `/dev/sdX` with your stick:
   ```bash
   sudo ./scripts/setup_usb.sh --data-size=512M /dev/sdX path/to/booto-<version>-amd64.iso
   ```
   - `--data-size=SIZE` sets the report partition, e.g. `256M` or `2G` (minimum `64M`). Leave it out to use the rest of the stick.
   - `--encrypt` or `--no-encrypt` decides whether the report partition gets a passphrase. Leave both out to be asked.
   - The script refuses disks that are not removable or that hold the running system.
3. When asked, type the device path again (e.g. `/dev/sdX`) to confirm.
4. Choose whether to protect the reports with a passphrase:
   - **Yes (default):** anyone who finds the stick cannot read the reports. Write the passphrase down: reports cannot be recovered without it.
   - **No:** Booto mounts the report partition at start without asking, and anyone with the stick can read the reports.

### Optional: capture memory before shutting down

Shutting down erases RAM, and with it any rootkit that lives only in memory. If the suspect machine runs Linux and is still on, capture its memory first with [AVML](https://github.com/microsoft/avml) (MIT, a single static binary):

1. On your own computer, download `avml` from its GitHub releases page and copy it to a second USB stick with more free space than the suspect's RAM.
2. On the suspect machine, plug in that stick and run, as root, writing only to the stick, never the suspect's own disk:
   ```bash
   sudo /media/<you>/<stick>/avml /media/<you>/<stick>/memory.lime
   sha256sum /media/<you>/<stick>/memory.lime > /media/<you>/<stick>/memory.lime.sha256
   ```
3. Analyse the capture later on your own computer with [Volatility 3](https://github.com/volatilityfoundation/volatility3), for example `vol -r json -f memory.lime linux.malware.hidden_modules > hidden.json`. Volatility needs a symbol table for the suspect's exact kernel.
4. Optional: copy `hidden.json` to the Booto stick and pass it to the disk scan with `booto -c --volatility hidden.json`. Booto prints each flagged row and sets the exit status to THREATS if there is one; it reads one JSON file per run.

Running any program on a compromised machine lets the rootkit see it, so treat the capture as a lead, not proof. Booto does not read the memory capture itself, only Volatility's JSON output.

### Optional: get the decryption keys before you start

Do this while the suspect machine still runs, if you can. An encrypted disk scanned without its key gives the verdict `INCOMPLETE`.

**BitLocker (Windows).** Your Windows login password or PIN does not unlock the disk: on most PCs the TPM chip holds the key, and Booto cannot use the TPM. You need the 48-digit **recovery key** (eight groups of six digits). Find it in one of these places:

- On the running Windows, in an administrator Command Prompt: `manage-bde -protectors -get C:`. The key is under **Numerical Password**. Run it for every encrypted drive letter (`manage-bde -status` lists them).
- In Windows: Control Panel > BitLocker Drive Encryption > **Back up your recovery key**. On Windows 11 Home, *Device encryption* keys are always stored in the Microsoft account.
- In your Microsoft account, from any device: <https://account.microsoft.com/devices/recoverykey> (or <https://aka.ms/myrecoverykey>).
- For a work or school PC: <https://aka.ms/aadrecoverykey>, or ask your IT department.
- On paper or a USB stick saved when BitLocker was turned on: a file named `BitLocker Recovery Key <ID>.TXT`.

When there are several keys, pick the one whose **Key ID** matches the drive. In Booto's root shell (F10), `cryptsetup bitlkDump /dev/<partition>` prints the drive's recovery key ID; compare its first 8 characters.

Get the key first: changing firmware settings to boot Booto (Secure Boot off, a new boot order) can make Windows ask for this recovery key the next time it starts.

**LUKS (Linux, such as Fedora or Ubuntu with disk encryption).** Use the passphrase you type at boot. There is no separate recovery key unless you added one (`systemd-cryptenroll --recovery-key`). If the disk unlocks only with the TPM or a FIDO key, add a passphrase while the system runs: `sudo cryptsetup luksAddKey /dev/<partition>`.

### Step 3: Boot the suspect machine

1. Shut the machine down completely (not sleep or hibernate).
2. Plug in the stick, open the boot menu (often `F12`, `F8`, `Esc` or `Option` on Macs) and choose the USB stick. If the firmware refuses it (owner-enrolled keys only), turn Secure Boot off for this boot.
3. Choose **Booto - Live Rootkit & Bootkit Forensic System** in the menu. The Booto TUI starts by itself on the first console.

### Step 4: Unlock the report partition

At boot a write blocker sets every disk except the Booto USB read-only (`blockdev --setro`) as soon as it appears.

Booto finds the `BOOTO_DATA` partition on the USB stick it booted from (never one on the suspect disk):

- **With a passphrase:** a box asks for it when the TUI starts. Type it and press `Enter`. Press `Esc` to skip; reports then go to RAM and are lost at power-off. Press `F4` to unlock later.
- **Without a passphrase:** it is mounted at start; nothing to do.
- **No report partition** (the ISO was written with `dd`, Rufus DD mode or caligula): press `F4` to create one, as below. This needs an ISO from 1.9.4-beta on; older ISOs have no partition table to add to.

#### Create, unlock, change or remove report storage

1. **Create:** press `F4` (or run `booto-storage create` in the root shell, `F10` then `S`). It shows the free space on the stick and asks:
   - `Report partition size in MiB [N]:` type a size from 64 to N, or press `Enter` to use all of it. The rest of the stick stays unallocated.
   - `Protect the reports with a passphrase? [Y/n]`: `Enter` encrypts it with LUKS2; `n` makes a plain ext4 partition anyone can read.
   - It confirms before writing, then asks for your passphrase twice and once more to format. There is no default passphrase and no recovery: a lost passphrase means lost reports.
2. **Unlock at the next boot:** the passphrase box appears when Booto starts; `Esc` skips it and `F4` asks again later. On another Linux computer, `cryptsetup open /dev/sdXN booto` then `mount -o ro /dev/mapper/booto /mnt` reads the reports.
3. **Change the passphrase:** in the root shell, `cryptsetup luksChangeKey /dev/sdXN`, where `sdXN` is the partition labelled `BOOTO_DATA` in `lsblk -o NAME,PARTLABEL` (partition 4 after `dd`, 2 with booto-writer). It works while the storage is unlocked; only the key slot changes, not the reports.
4. **Resize or remove encryption:** `booto-storage delete` (it erases every report; copy them off first), then create it again with the new size or answer `n`.

The Reports pane shows `Storage on USB, N MiB free` when reports will be saved to the stick.

### Step 5: Scan

In the TUI:

1. Move to the target disk with the arrow keys and press `Space` to mark it as the target. Booto only ever mounts it read-only.
2. For an encrypted target, press `F3` and enter its passphrase (for BitLocker, its password or 48-digit recovery key, with or without the dashes). It is unlocked read-only.
3. Optionally turn engines on or off in the module list with `Space`.
4. Press `F5` to scan. The result is `CLEAN`, `THREATS` (a HIGH or CRITICAL finding), `SUSPICIOUS` (only MEDIUM or lower findings: check each against what the owner installed) or `INCOMPLETE` (an engine could not run, so the disk is not proven clean).
5. Press `2` for the Findings page (every finding with its rule, hash and detail), `3` for Firmware, `4` for Evidence (before/after hash of the target, quarantine, what each engine read, and ready-to-paste `--acquire`, `--undelete` and `--hashlist` commands for the target). `1` or `Esc` returns to the panes.
6. Press `F6` to save the reports to `/persistence/cases`.

Without the TUI (from the root shell):

```bash
booto -c -t /dev/nvme0n1p2 -p /persistence/cases   # exit code 0 CLEAN, 1 THREATS, 2 INCOMPLETE, 3 SUSPICIOUS
booto -c -t /dev/nvme0n1p2 -d                      # dry run: show the plan, touch nothing
booto -c -t /dev/nvme0n1p3 --undelete /persistence/cases/recovered   # NTFS: copy deleted files out, read-only
```

### Step 6: Finish and check the reports

1. Press `F10`, then `p` to power off. Booto unmounts and locks the report partition first, so reports are safe to carry away.
2. On your own computer, open the stick's second partition (enter the passphrase if it has one) and check that no report was changed:
   ```bash
   cd /path/to/mounted/cases && sha256sum -c case_*.sha256
   ```
   Each report has a `.json` (one line, for tools) and a `.md` (for people) file. The `.sha256` files only catch accidental changes; the `.sig` files prove the report came from this stick:
   ```bash
   openssl pkeyutl -verify -pubin -inkey booto_report_key.pub -rawin -in case_X.json -sigfile case_X.json.sig
   ```
   It must print `Signature Verified Successfully`. Each stick makes its own Ed25519 key on first export and keeps the private half in `keys/` on the report partition, outside `cases/`; keep a copy of `booto_report_key.pub` from a known-good run, because anyone who can write the partition can also replace the key.

## 4. Limits

- The package check trusts the package lists on the suspect disk; an attacker with root access can rewrite them.
- Booto examines the disk only. It cannot see malware that lives only in the suspect machine's RAM, because that machine is powered off before Booto boots; capture memory first if you need it (see the optional step above).
- On an older or unrecognised Intel chipset, `booto -c -t <disk>` prints three commands whose output helps confirm the chipset; paste it in a [GitHub issue](https://github.com/Dellrall/Booto/issues).
