/*
 * Booto YARA rules: matched against every PE image the UEFI and Windows boot checks read, every kernel module,
 * and every ELF file inside the initramfs. Each rule needs string metas "severity" (INFO..CRITICAL) and
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
