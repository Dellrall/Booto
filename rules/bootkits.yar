/*
 * Booto YARA rules: matched against every PE image the UEFI and Windows boot checks read, every kernel module,
 * every ELF file inside the initramfs and every installed program and library, and the -x SPI flash dump. Each rule needs string metas "severity" (INFO..CRITICAL) and
 * "description". PE matches on an image with a valid Microsoft signature are not reported.
 * Sign with scripts/update_rules.sh after any change.
 */

rule BOOTO_YARA_EMBEDDED_PE
{
    meta:
        severity = "MEDIUM"
        description = "Boot image carries a second Windows executable inside it, as droppers and bootkit installers do"
    strings:
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        uint16(0) == 0x5A4D and
        for any i in (1..#dos_stub) : (@dos_stub[i] >= 0x200 and uint16(@dos_stub[i] - 0x4E) == 0x5A4D)
}

rule BOOTO_YARA_EFIGUARD
{
    meta:
        severity = "HIGH"
        description = "References EfiGuard, a public tool that disables Windows PatchGuard and driver signature checks at boot"
    strings:
        $name = "EfiGuard" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $name
}

rule BOOTO_YARA_LKM_ROOTKIT_MODINFO
{
    meta:
        severity = "HIGH"
        description = "Kernel module calls itself a rootkit in its module info, as Diamorphine and its many forks do"
    strings:
        $info = /(description|author|name)=[^\x00]{0,80}rootkit/ nocase
    condition:
        uint32(0) == 0x464C457F and $info
}

rule BOOTO_YARA_LINUX_ROOTKIT_FAMILY
{
    meta:
        severity = "HIGH"
        description = "Names a public Linux rootkit (Diamorphine, Reptile, KoviD, Azazel, Jynx, BEURK, bdvl, Vlany)"
    strings:
        $diamorphine = "diamorphine" fullword nocase
        $reptile1 = "reptile_cmd" fullword
        $reptile2 = "reptile_shell" fullword
        $kovid = "kovid" fullword nocase
        $azazel = "azazel" fullword nocase
        $jynx = "jynx" fullword nocase
        $beurk = "beurk" fullword nocase
        $bdvl = "bdvl" fullword nocase
        $vlany = "vlany" fullword nocase
    condition:
        uint32(0) == 0x464C457F and any of them
}

rule BOOTO_YARA_LKM_SYSCALL_HOOK
{
    meta:
        severity = "HIGH"
        description = "Kernel module looks up hidden kernel symbols and names the syscalls rootkits hook to hide files and processes"
    strings:
        $getdents = "__x64_sys_getdents64"
        $kill = "__x64_sys_kill"
        $lookup1 = "kallsyms_lookup_name"
        $lookup2 = "register_kprobe"
    condition:
        uint32(0) == 0x464C457F and uint16(16) == 1 and $getdents and $kill and any of ($lookup*)
}

rule BOOTO_YARA_LKM_NET_HIDE
{
    meta:
        severity = "HIGH"
        description = "Kernel module looks up hidden kernel symbols and names tcp4_seq_show, the /proc/net/tcp handler rootkits hook to hide connections"
    strings:
        $tcp = "tcp4_seq_show"
        $lookup1 = "kallsyms_lookup_name"
        $lookup2 = "register_kprobe"
        $lookup3 = "register_ftrace_function"
    condition:
        uint32(0) == 0x464C457F and uint16(16) == 1 and $tcp and any of ($lookup*)
}

rule BOOTO_YARA_BPFDOOR
{
    meta:
        severity = "HIGH"
        description = "BPFDoor backdoor: its lock and pid file paths, fake process name or magic passwords"
    strings:
        $f1 = "/dev/shm/kdmtmpflush"
        $f2 = "/var/run/haldrund.pid"
        $f3 = "/var/run/xinetd.lock"
        $name = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event"
        $pw1 = "justtryit" fullword
        $pw2 = "justforfun" fullword
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule BOOTO_YARA_PUMAKIT
{
    meta:
        severity = "HIGH"
        description = "PUMAKIT Linux rootkit: its staging folder, or the zarya loader with the puma config"
    strings:
        $zov = "/usr/share/zov_f"
        $zarya = "zarya" fullword
        $puma = ".puma-config"
    condition:
        uint32(0) == 0x464C457F and ($zov or ($zarya and $puma))
}

rule BOOTO_YARA_XORDDOS
{
    meta:
        severity = "HIGH"
        description = "XorDDoS: the XOR key its rootkit-backed Linux trojan encrypts its config with"
    strings:
        $key = "BB2FA36AAA9541F0"
    condition:
        uint32(0) == 0x464C457F and $key
}

rule BOOTO_YARA_BOOTKITTY
{
    meta:
        severity = "CRITICAL"
        description = "Names Bootkitty, the first public UEFI bootkit aimed at Linux (2024)"
    strings:
        $name = "Bootkitty" ascii wide nocase
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and $name
}

/* FwHunt threat rules by Binarly (CC0-1.0, https://github.com/binarly-io/FwHunt), ported to YARA: code and string
 * patterns only. No file-header check, so they also match a raw SPI flash image and its inflated LZMA sections. */

rule BOOTO_YARA_BLACKLOTUS
{
    meta:
        severity = "CRITICAL"
        description = "BlackLotus UEFI bootkit: its encoded strings or its winload trampoline hook (FwHunt)"
    strings:
        $s1 = { 99 00 95 00 03 00 02 00 aa 00 a1 00 0e 00 0f 00 02 00 1b 00 1e 00 1d 00 88 00 93 00 00 00 93 00 1e 00 84 00 12 00 07 00 1c 00 1d 00 1d 00 06 00 0a 00 9f 00 11 00 0b 00 0f 00 0c 00 a5 00 }
        $s2 = { 94 00 9c 00 09 00 04 00 03 00 0b 00 1a 00 0a 00 9d 00 8d 00 0a 00 0c 00 03 00 1f 00 83 00 06 00 94 00 c2 00 }
        $s3 = { 1c 00 08 00 0b 00 01 00 dc 00 c3 00 0a 00 08 00 1b 00 16 00 0d 00 af 00 }
        $s4 = { 1c 00 08 00 0b 00 01 00 dc 00 ca 00 01 00 0a 00 0e 00 12 00 1f 00 03 00 af 00 }
        $c1 = { 41 b8 09 00 00 d0 }
        $c2 = { ff 25 00 00 00 00 }
        $c3 = { 48 8b d1 41 b8 0e 00 00 00 48 8b c8 e8 ?? ?? ?? ?? 41 b8 06 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 48 89 7b 06 }
    condition:
        any of ($s*) or all of ($c*)
}

rule BOOTO_YARA_ESPECTER
{
    meta:
        severity = "CRITICAL"
        description = "ESPecter bootkit: EFI loader code that patches Windows boot manager integrity checks (FwHunt)"
    strings:
        $c = { 81 3f ff 48 83 65 ?? ?? 81 7f 04 d0 00 48 83 ?? ?? 81 7f 08 65 40 00 83 ?? ?? 90 90 c6 47 eb b8 c7 47 ec 00 00 00 00 c6 47 f0 c3 48 31 c0 }
    condition:
        $c
}

rule BOOTO_YARA_COSMICSTRAND
{
    meta:
        severity = "CRITICAL"
        description = "CosmicStrand firmware rootkit: HandleProtocol hook planted in the CSMCORE driver (FwHunt)"
    strings:
        $c = { 48 8b 0c 24 50 53 51 52 55 56 57 41 52 41 53 41 54 41 55 41 56 41 57 48 83 ec 60 48 b8 48 85 c0 74 07 33 c0 e9 48 39 01 75 ?? 48 b8 a1 31 1b 5b 62 95 d2 11 48 3b 02 75 ?? 48 b8 8e 3f 00 a0 c9 69 72 3b 48 3b 42 08 75 ?? 4c 8b 3d ?? ?? ?? ?? 4d 8b 30 49 89 cd 4d 8b 46 48 4d 89 e9 49 8b 56 40 4c 89 f9 e8 }
    condition:
        $c
}

rule BOOTO_YARA_MOONBOUNCE
{
    meta:
        severity = "CRITICAL"
        description = "MoonBounce firmware implant: CORE_DXE boot service hooks and kernel-transfer search (FwHunt)"
    strings:
        $h1 = { c6 00 48 c7 40 01 8b c4 48 89 9c 53 51 52 41 50 41 51 56 57 48 83 ec 38 e8 00 00 00 00 }
        $h2 = { c6 00 48 c7 40 01 89 5c 24 08 9c 53 51 52 41 50 41 51 56 57 48 83 ec 48 e8 00 00 00 00 }
        $h3 = { c6 00 48 c7 40 01 89 5c 24 08 48 8b 44 24 08 9c 53 51 52 41 50 41 51 56 57 31 c9 ff c1 81 f9 78 88 15 00 }
        $search = { ff c1 81 f9 78 88 15 00 ?? ?? 67 81 3c 08 41 55 48 cb }
    condition:
        any of ($h*) and $search
}

rule BOOTO_YARA_LOJAX
{
    meta:
        severity = "CRITICAL"
        description = "LoJax firmware implant: SecDxe driver that drops rpcnetp.exe onto the Windows disk (FwHunt)"
    strings:
        $ntfs = "NTFS File System Driver" wide
        $drop = "rpcnetp.exe" wide
        $autochk = "autoche.exe" wide
    condition:
        all of them
}

rule BOOTO_YARA_MOSAICREGRESSOR
{
    meta:
        severity = "CRITICAL"
        description = "MosaicRegressor firmware implant: SmmInterfaceBase dropper code or SmmAccessSub Startup payload (FwHunt)"
    strings:
        $code = { c6 00 04 48 8b 44 24 ?? c6 40 01 06 48 8b 44 24 ?? c6 40 02 14 48 8b 44 24 ?? c6 40 03 00 48 8b 4c 24 ?? 48 83 c1 04 41 b8 10 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? ff 90 60 01 00 00 }
        $log = "setupinf.log" wide
        $exe = "IntelUpdate.exe" wide
        $startup = { 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 00 00 }
    condition:
        $code or ($log and $exe and $startup)
}
