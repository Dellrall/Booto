/*
 * Booto YARA rules: matched against every PE image the UEFI and Windows boot checks read.
 * Each rule needs string metas "severity" (INFO..CRITICAL) and "description". Matches on an image with a valid
 * Microsoft signature are not reported. Sign with scripts/update_rules.sh after any change.
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
