# Booto setup guide

How to put Booto on a USB stick, boot a suspect machine from it, scan the machine's disk and keep the reports.

## 1. Specification

### Machine being examined

| Item | Requirement |
| :--- | :--- |
| CPU | 64-bit x86 (amd64). ARM machines and Apple Silicon Macs cannot boot it. |
| Firmware | UEFI or legacy BIOS; the ISO boots in both modes. |
| Secure Boot | **Must be turned off** in the firmware setup. Booto's bootloader is not signed. The firmware audit then reports Secure Boot as off; that is expected for this boot. |
| RAM | 2 GiB minimum (the QEMU test VM uses 2048 MiB). The live system runs from RAM and never writes to the internal disks. |
| Boot source | Must allow booting from USB. The live system only loads from removable media (USB stick, CD/DVD). A USB SSD that reports itself as non-removable boots only via the "USB not detected" GRUB entry (finds this build's ISO by UUID). |
| Disk being scanned | Any disk Linux can mount read-only. The package check needs a Debian-based system (Debian, Ubuntu, Mint, Kali); other systems show it as `SKIPPED`. Encrypted (LUKS) disks can be unlocked read-only from the TUI (`F3`). |

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

1. Download `booto-v1.4.0-amd64.iso` and `booto-v1.4.0-amd64.iso.sha256` from <https://github.com/Dellrall/Booto/releases/latest>.
2. Check the download: `sha256sum -c booto-v1.4.0-amd64.iso.sha256`. It must print `OK`.

Option B, build it yourself (about 10 minutes):

```bash
git clone https://github.com/Dellrall/Booto.git && cd Booto
sudo make iso          # writes dist/booto-live-amd64.iso
```

Optional check in a VM: `./scripts/run_qemu_vm.sh`.

### Step 2: Write the USB stick

1. Plug in the stick and find its device name. The `TRAN` column must say `usb`:
   ```bash
   lsblk -d -o NAME,SIZE,MODEL,TRAN
   ```
2. Run the installer. **This erases the whole stick.** Replace `/dev/sdX` with your stick:
   ```bash
   sudo ./scripts/setup_usb.sh --data-size=512M /dev/sdX path/to/booto-v1.4.0-amd64.iso
   ```
   - `--data-size=SIZE` sets the report partition, e.g. `256M` or `2G` (minimum `64M`). Leave it out to use the rest of the stick.
   - `--encrypt` or `--no-encrypt` decides whether the report partition gets a passphrase. Leave both out to be asked.
   - The script refuses disks that are not removable or that hold the running system.
3. When asked, type the device path again (e.g. `/dev/sdX`) to confirm.
4. Choose whether to protect the reports with a passphrase:
   - **Yes (default):** anyone who finds the stick cannot read the reports. Write the passphrase down: reports cannot be recovered without it.
   - **No:** Booto mounts the report partition at start without asking, and anyone with the stick can read the reports.

### Step 3: Boot the suspect machine

1. Shut the machine down completely (not sleep or hibernate).
2. Plug in the stick, open the boot menu (often `F12`, `F8`, `Esc` or `Option` on Macs) and choose the USB stick. Turn off Secure Boot first if the stick is refused.
3. Choose **Booto - Live Rootkit & Bootkit Forensic System** in the menu. The Booto TUI starts by itself on the first console.

### Step 4: Unlock the report partition

Booto finds the `BOOTO_DATA` partition on the USB stick it booted from (never one on the suspect disk):

- **With a passphrase:** a box asks for it when the TUI starts. Type it and press `Enter`. Press `Esc` to skip; reports then go to RAM and are lost at power-off. Press `F4` to unlock later.
- **Without a passphrase:** it is mounted at start; nothing to do.

The Reports pane shows `Storage on USB, N MiB free` when reports will be saved to the stick.

### Step 5: Scan

In the TUI:

1. Move to the target disk with the arrow keys and press `Space` to mark it as the target. Booto only ever mounts it read-only.
2. For an encrypted target, press `F3` and enter its passphrase. It is unlocked read-only.
3. Optionally turn engines on or off in the module list with `Space`.
4. Press `F5` to scan. The result is `CLEAN`, `THREATS` or `INCOMPLETE` (an engine could not run, so the disk is not proven clean).
5. Press `F6` to save the reports to `/persistence/cases`.

Without the TUI (from the root shell):

```bash
booto -c -t /dev/nvme0n1p2 -p /persistence/cases   # exit code 0 CLEAN, 1 THREATS, 2 INCOMPLETE
booto -c -t /dev/nvme0n1p2 -d                      # dry run: show the plan, touch nothing
```

### Step 6: Finish and check the reports

1. Press `F10`, then `p` to power off. Booto unmounts and locks the report partition first, so reports are safe to carry away.
2. On your own computer, open the stick's second partition (enter the passphrase if it has one) and check that no report was changed:
   ```bash
   cd /path/to/mounted/cases && sha256sum -c case_*.sha256
   ```
   Each report has a `.json` (one line, for tools) and a `.md` (for people) file. The `.sha256` files are integrity checksums, not signatures.

## 4. Limits

- The package check trusts the package lists on the suspect disk; an attacker with root access can rewrite them.
- Booto examines the disk only. It cannot see malware that lives only in the suspect machine's RAM, because that machine is powered off before Booto boots.
- On an older or unrecognised Intel chipset, `booto -c -t <disk>` prints three commands whose output helps confirm the chipset; paste it in a [GitHub issue](https://github.com/Dellrall/Booto/issues).
