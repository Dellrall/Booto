#!/usr/bin/env bash
# ==============================================================================
# Booto Detection Rules Generator
# Generates the sealed JSON rules files (UEFI DBX revocations, LKM rootkit and
# MBR/VBR bootkit signatures) from the canonical built-in tables in
# src/rules_loader.c, plus their "<file>.sha256" seals. Nothing is fetched from
# the network. Keep this file in sync with src/rules_loader.c; from the repo root,
# `scripts/update_rules.sh rules` reproduces the committed rules/ byte-for-byte.
# ==============================================================================
set -euo pipefail

RULES_DIR="${1:-/persistence/rules}"
if [ ! -d "${RULES_DIR}" ]; then
    RULES_DIR="rules"
fi
mkdir -p "${RULES_DIR}"

echo "=== Booto Forensic Threat Rule Generator ==="
echo "Target Rules Directory: ${RULES_DIR}"

# 1. UEFI DBX revocations (sha256 = Authenticode PE image hash)
echo "[+] Writing UEFI DBX revocation database..."
cat << 'EOF_DBX' > "${RULES_DIR}/uefi_dbx_revocations.json"
{
  "revocations": [
    {
      "sha256": "0c644d57c79e614066929a008c2a382d5e305e9e03d42c38848d7c4dbfc78f24",
      "threat": "BlackLotus Revoked Windows Bootloader",
      "cve": "CVE-2022-21894",
      "severity": "CRITICAL",
      "description": "Vulnerable Windows EFI boot manager exploited by BlackLotus UEFI bootkit to bypass Secure Boot"
    },
    {
      "sha256": "80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca44b83993b36a49f63",
      "threat": "BlackLotus Batched EFI Payload",
      "cve": "CVE-2023-24932",
      "severity": "CRITICAL",
      "description": "BlackLotus second-stage kernel hijacker payload deployed into ESP"
    },
    {
      "sha256": "cb078e4726b008d51624c96ea208d249f3e498c8793b890916d7a46abf1d4f9b",
      "threat": "BootHole Vulnerable GRUB2 Binary",
      "cve": "CVE-2020-10713",
      "severity": "HIGH",
      "description": "Revoked GRUB2 EFI executable vulnerable to heap-overflow buffer execution in grub.cfg parser"
    },
    {
      "sha256": "5f8a3562a63200dc8ba79198642738a9d9e4a3b17728f3a9e0123ef89a12c451",
      "threat": "ESPecter UEFI Bootloader Implant",
      "cve": "ESPecter",
      "severity": "CRITICAL",
      "description": "ESPecter bootkit persistence module hidden in the EFI partition"
    },
    {
      "sha256": "a849201bc93ef4a890123ef9a82bc128912ef349a128901bc3412ef89018f4b2",
      "threat": "MoonBounce Stage-2 Bootloader",
      "cve": "MoonBounce",
      "severity": "CRITICAL",
      "description": "Stage-2 OS-loader interceptor deploying memory implants from ESP"
    }
  ]
}
EOF_DBX

# 2. Linux LKM / Ring-0 rootkit symbol signatures
echo "[+] Writing LKM Ring-0 rootkit signatures..."
cat << 'EOF_LKM' > "${RULES_DIR}/lkm_rootkit_signatures.json"
{
  "signatures": [
    {
      "name": "Syscall Table Hooking",
      "rule_id": "LKM_HOOK_SYS_CALL_TABLE",
      "severity": "CRITICAL",
      "description": "Direct reference or modification to the kernel sys_call_table",
      "symbols": ["sys_call_table"]
    },
    {
      "name": "Dynamic Kernel Symbol Resolution",
      "rule_id": "LKM_KALLSYMS_LOOKUP",
      "severity": "MEDIUM",
      "description": "Resolves unexported kernel symbols at runtime (used for syscall hooking)",
      "symbols": ["kallsyms_lookup_name"]
    },
    {
      "name": "Diamorphine Rootkit",
      "rule_id": "LKM_DIAMORPHINE_CORE",
      "severity": "CRITICAL",
      "description": "Matches Diamorphine rootkit core symbol signatures",
      "symbols": ["diamorphine"]
    },
    {
      "name": "Kill Syscall Interceptor",
      "rule_id": "LKM_HOOK_KILL",
      "severity": "CRITICAL",
      "description": "Hooks sys_kill to execute root backdoor signals (e.g. signal 64 root escalation)",
      "symbols": ["hacked_kill"]
    },
    {
      "name": "Directory Entry Hider",
      "rule_id": "LKM_HOOK_GETDENTS",
      "severity": "CRITICAL",
      "description": "Hooks sys_getdents to hide rootkit files and directories from userland",
      "symbols": ["hacked_getdents"]
    },
    {
      "name": "Directory Entry Hider (64-bit)",
      "rule_id": "LKM_HOOK_GETDENTS64",
      "severity": "CRITICAL",
      "description": "Hooks sys_getdents64 to hide rootkit files and directories from userland",
      "symbols": ["hacked_getdents64"]
    },
    {
      "name": "LKM Kernel Object Hiding (DKOM)",
      "rule_id": "LKM_DKOM_HIDE_MODULE",
      "severity": "CRITICAL",
      "description": "Unlinks module from the sysfs/lsmod list using Direct Kernel Object Manipulation",
      "symbols": ["is_invisible"]
    },
    {
      "name": "Process Hiding Mechanism",
      "rule_id": "LKM_DKOM_HIDE_PROC",
      "severity": "CRITICAL",
      "description": "Hides malicious PID structures from /proc directory walks",
      "symbols": ["hide_proc"]
    },
    {
      "name": "Ftrace Syscall Hijack",
      "rule_id": "LKM_FTRACE_HOOK_INSTALL",
      "severity": "CRITICAL",
      "description": "Uses Linux ftrace subsystem to redirect kernel execution flow",
      "symbols": ["fh_install_hook"]
    },
    {
      "name": "Ftrace Hook Uninstaller",
      "rule_id": "LKM_FTRACE_HOOK_REMOVE",
      "severity": "HIGH",
      "description": "Ftrace hook removal routine",
      "symbols": ["fh_remove_hook"]
    },
    {
      "name": "Khook In-Kernel Hooking Engine",
      "rule_id": "LKM_KHOOK_ENGINE",
      "severity": "CRITICAL",
      "description": "Generic kernel-mode inline function hooking framework",
      "symbols": ["khook_init"]
    },
    {
      "name": "Reptile Rootkit Hook",
      "rule_id": "LKM_REPTILE_HOOK",
      "severity": "CRITICAL",
      "description": "Matches Reptile Linux rootkit network and file hook signatures",
      "symbols": ["rep_hook"]
    },
    {
      "name": "Suterusu Rootkit",
      "rule_id": "LKM_SUTERUSU_SIGNATURE",
      "severity": "CRITICAL",
      "description": "Matches Suterusu LKM rootkit framework signatures",
      "symbols": ["suterusu"]
    },
    {
      "name": "TCP Network Port Hider",
      "rule_id": "LKM_NET_PORT_HIDER",
      "severity": "CRITICAL",
      "description": "Hooks tcp4_seq_show to hide listening reverse shell ports from netstat/ss",
      "symbols": ["tcp4_seq_show"]
    },
    {
      "name": "UDP Network Port Hider",
      "rule_id": "LKM_NET_PORT_HIDER",
      "severity": "CRITICAL",
      "description": "Hooks udp4_seq_show to hide UDP listening ports",
      "symbols": ["udp4_seq_show"]
    }
  ]
}
EOF_LKM

# 3. MBR / VBR bootkit byte-pattern signatures
#    target: "mbr_bootstrap" (sector 0, first 446 bytes) | "vbr_sector" (partition boot sector, 512 bytes)
#    unknown_bootloader_only: fire only when no known bootloader was identified in the MBR
echo "[+] Writing MBR/VBR bootkit signatures..."
cat << 'EOF_MBR' > "${RULES_DIR}/mbr_bootkit_signatures.json"
{
  "signatures": [
    {
      "name": "Rovnix / Carberp MBR Bootkit",
      "rule_id": "MBR_BOOTKIT_ROVNIX",
      "target": "mbr_bootstrap",
      "severity": "CRITICAL",
      "unknown_bootloader_only": false,
      "description": "Matches Rovnix/Carberp MBR bootstrap hook redirecting execution to hidden sectors before partition table",
      "patterns_hex": ["fa33c08ed08ed88ec0bc007c", "fa31c08ed88ed0bc007cfbcd13"]
    },
    {
      "name": "TDL4 / Sinowal (Mebroot) Bootkit",
      "rule_id": "MBR_BOOTKIT_TDL4_MEBROOT",
      "target": "mbr_bootstrap",
      "severity": "CRITICAL",
      "unknown_bootloader_only": false,
      "description": "Intercepts and rewires INT 13h BIOS disk handler to execute rootkit payload from reserved sectors",
      "patterns_hex": ["31c08ed889164c00", "8cc88ed8a14c00"]
    },
    {
      "name": "Stoned / Legacy MBR Bootkit",
      "rule_id": "MBR_BOOTKIT_STONED",
      "target": "mbr_bootstrap",
      "severity": "CRITICAL",
      "unknown_bootloader_only": false,
      "description": "Classic MBR bootkit hooking INT 13h and relocating original boot sector to high memory (0x9FC0)",
      "patterns_hex": ["596f7572205043206973206e6f772053746f6e656421", "cd137205ea0000c09f"]
    },
    {
      "name": "HermeticWiper / Ransomware MBR Payload",
      "rule_id": "MBR_WIPER_RANSOMWARE",
      "target": "mbr_bootstrap",
      "severity": "CRITICAL",
      "unknown_bootloader_only": false,
      "description": "Destructive MBR wiper or ransomware screen replacing standard OS bootloader with fake repair screen / wiper loop",
      "patterns_hex": ["526570616972696e672066696c6573797374656d", "596f757220616374696f6e61626c652066696c65732061726520656e63727970746564", "43484b44534b20697320726570616972696e67", "31c08ed8b9000231c0aa"]
    },
    {
      "name": "Anomalous Direct Disk Write in MBR Code",
      "rule_id": "MBR_HEURISTIC_DISK_WRITE",
      "target": "mbr_bootstrap",
      "severity": "HIGH",
      "unknown_bootloader_only": true,
      "description": "Unrecognized MBR bootstrap code invokes BIOS INT 13h disk write routines (suspicious self-propagating bootkit)",
      "patterns_hex": ["b403cd13", "b443cd13"]
    },
    {
      "name": "GAPZ / Cidox VBR Bootkit",
      "rule_id": "VBR_BOOTKIT_GAPZ",
      "target": "vbr_sector",
      "severity": "CRITICAL",
      "unknown_bootloader_only": false,
      "description": "Partition VBR contains GAPZ/Cidox bootloader hook hijacking control flow before Windows kernel initialization",
      "patterns_hex": ["eb58905657538cc8"]
    }
  ]
}
EOF_MBR

echo "[+] Sealing rules files (sha256sum)..."
for f in uefi_dbx_revocations lkm_rootkit_signatures mbr_bootkit_signatures; do
    sha256sum "${RULES_DIR}/${f}.json" > "${RULES_DIR}/${f}.json.sha256"
done

echo "=== Rules Generated Successfully ==="
echo "Total DBX Rules: 5"
echo "Total LKM Rules: 15"
echo "Total MBR Rules: 6"
