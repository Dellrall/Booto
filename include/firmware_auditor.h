/**
 * @file firmware_auditor.h
 * @brief Read-only audit of the host machine's firmware: Secure Boot key state
 *        (efivars), PKfail test keys, dbx presence, DMA protection (ACPI DMAR/IVRS,
 *        Thunderbolt) and silicon locks (SMM lock, SMRAM range, BIOS write protection).
 *        Describes the machine Booto booted on, not the scanned disk.
 */
#ifndef BOOTO_FIRMWARE_AUDITOR_H
#define BOOTO_FIRMWARE_AUDITOR_H

#include "booto.h"
#include "yara_scan.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FW_RESULT_PASS, FW_RESULT_FAIL, FW_RESULT_UNKNOWN, FW_RESULT_NA } fw_result_t;

typedef enum {
    FW_CHECK_SECURE_BOOT,      /* "Secure Boot on" */
    FW_CHECK_SETUP_MODE,       /* "Setup mode off" */
    FW_CHECK_PLATFORM_KEY,     /* "Platform key" */
    FW_CHECK_TEST_KEYS,        /* "No test keys (PKfail)" */
    FW_CHECK_DBX,              /* "Revocation list (dbx)" */
    FW_CHECK_DB_2023,          /* "2023 Microsoft CA in db" */
    FW_CHECK_MOK,              /* "Shim MOK keys known" */
    FW_CHECK_BOOT_ENTRY,       /* "No pending BootNext" */
    FW_CHECK_IOMMU,            /* "IOMMU described (DMAR/IVRS)" */
    FW_CHECK_THUNDERBOLT_DMA,  /* "Thunderbolt DMA protection" */
    FW_CHECK_SMM_LOCK,         /* "SMM locked" */
    FW_CHECK_SMRAM_RANGE,      /* "SMRAM range protected" */
    FW_CHECK_BIOS_WP,          /* "BIOS write protection" */
    FW_CHECK_TPM_LOG,          /* "Boot measurements (TPM)" */
    FW_CHECK_ME_STATE,         /* "Intel ME normal mode" */
    FW_CHECK_BOOT_GUARD,       /* "Boot Guard verified boot" */
    FW_CHECK_DEBUG_LOCK,       /* "CPU debug interface locked" */
    FW_CHECK_COUNT
} fw_check_id_t;

typedef struct {
    fw_result_t result;
    char detail[160];          /* one plain sentence */
} fw_check_t;

typedef struct {
    bool uefi_boot;                     /* efivars directory exists */
    bool chipset_unconfirmed;           /* Intel layout from an unverified table, or chipset not recognised */
    fw_check_t checks[FW_CHECK_COUNT];
    int fail_count;
    int unknown_count;
} firmware_report_t;

/* What to send so a chipset can be confirmed; commands exist on the live ISO (no lspci, no sudo). */
#define FW_CHIPSET_HELP \
    "Booto has not been confirmed on this chipset. To help, run as root:\n" \
    "  od -A x -t x1 /sys/bus/pci/devices/0000:00:00.0/config\n" \
    "  od -A x -t x1 /sys/bus/pci/devices/0000:00:1f.0/config\n" \
    "  grep -m2 -E '^(cpu family|model)[[:space:]]*:' /proc/cpuinfo\n" \
    "and paste the output in an issue at https://github.com/Dellrall/Booto/issues\n"

typedef struct {
    const char *efivars_dir;
    const char *acpi_tables_dir;
    const char *thunderbolt_dir;
    const char *cpuinfo_path;
    const char *msr_dir;       /* holds <cpu>/msr */
    const char *pci_devices_dir;
    const char *tpm_dir;       /* holds pcr-sha256/<n> */
    const char *tpm_log_path;  /* TCG PC Client binary event log */
    const char *mei_dir;       /* Intel ME: fw_status, fw_ver */
    const char *ccp_dir;       /* AMD security processor driver: <bdf>/{debug_lock_on,fused_part,rom_armor_enforced} */
} firmware_paths_t;

/**
 * @brief Audit host firmware state. Never writes to any firmware interface.
 * @param paths NULL (or NULL fields) = /sys/firmware/efi/efivars, /sys/firmware/acpi/tables,
 *              /sys/bus/thunderbolt/devices, /proc/cpuinfo, /dev/cpu, /sys/bus/pci/devices,
 *              /sys/class/tpm/tpm0, /sys/kernel/security/tpm0/binary_bios_measurements,
 *              /sys/class/mei/mei0, /sys/bus/pci/drivers/ccp.
 * @return BOOTO_OK whenever out != NULL (unreadable checks carry UNKNOWN);
 *         BOOTO_ERR_INVALID_ARG if out is NULL.
 */
booto_error_t firmware_audit(const firmware_paths_t *paths, firmware_report_t *out);

/* Crypto-agile TCG event log (untrusted bytes): copies the SHA-256 digest of each EFI application the firmware
 * loaded (EV_EFI_BOOT_SERVICES_APPLICATION, the image's Authenticode hash) into apps, at most max_apps.
 * Returns how many, or -1 when the log is malformed or has no SHA-256 bank. */
int firmware_tpm_log_apps(const uint8_t *log, size_t len, uint8_t (*apps)[32], int max_apps);

/* Expert mode (--expert-firmware, off by default): deeper reads that need root and take longer. */
#define FW_NVRAM_MAX_FINDINGS 32
typedef struct {
    char name[256];            /* efivarfs entry, Name-GUID */
    char reason[96];
    size_t size;               /* data bytes, without the 4-byte attributes */
} fw_nvram_finding_t;

typedef struct {
    int vars_scanned;
    int unreadable;
    int count;
    fw_nvram_finding_t findings[FW_NVRAM_MAX_FINDINGS];
} fw_nvram_report_t;

/**
 * @brief Flag UEFI variables that hide code: a PE or ELF image anywhere in the data, or a large
 *        high-entropy blob that is not a signature database. Read-only.
 * @param efivars_dir NULL = /sys/firmware/efi/efivars.
 * @return BOOTO_OK; BOOTO_ERR_NOT_FOUND if the directory cannot be opened; BOOTO_ERR_INVALID_ARG if out is NULL.
 */
booto_error_t firmware_nvram_scan(const char *efivars_dir, fw_nvram_report_t *out);

/**
 * @brief Read the SPI flash with `flashrom -p internal -r out_path` (never writes the chip) and hash the image.
 *        If the full read fails (locked ME region), retries with `--ifd -i bios` and sets *bios_only.
 * @return BOOTO_OK with sha256_hex set; BOOTO_ERR_NOT_FOUND if flashrom is not installed;
 *         BOOTO_ERR_IO if flashrom failed (not root, or chipset locked) or the image cannot be hashed.
 */
booto_error_t firmware_spi_dump(const char *out_path, char sha256_hex[65], bool *bios_only);

typedef struct {
    int volumes;          /* UEFI firmware volumes (_FVH) */
    int lzma_sections;    /* LZMA-compressed sections found */
    int lzma_inflated;    /* of those, inflated by the sandboxed xz */
    int pe_images;        /* PE images, raw or inside inflated sections */
    int windows_pe;       /* PE images built for Windows (GUI/console subsystem): firmware never runs these */
    int yara_count;       /* distinct YARA rules matched in the image or an inflated section */
    yara_match_t yara[YARA_MAX_MATCHES];
    int descriptor_writable; /* firmware_ifd_descriptor_writable() of the image */
} fw_spi_report_t;

/**
 * @brief Read the Intel flash descriptor's BIOS master (FLMSTR1) of a SPI image (untrusted bytes).
 * @return 1 if the host CPU may rewrite the descriptor region (fwupd Spi.Descriptor fails), 0 if it may not,
 *         -1 if there is no descriptor or its layout is not recognised.
 */
int firmware_ifd_descriptor_writable(const uint8_t *d, size_t len);

/**
 * @brief Walk a dumped SPI image: count firmware volumes, inflate LZMA sections with the sandboxed
 *        `xz --format=lzma`, count PE images and match the signed YARA rules against both. A Windows PE inside firmware is how WPBT-style and
 *        MosaicRegressor-style implants drop a payload into the OS (some vendor tools do this too).
 * @return BOOTO_OK; BOOTO_ERR_IO if the image cannot be read; BOOTO_ERR_INVALID_ARG on NULL.
 */
booto_error_t firmware_spi_analyze(const char *image_path, fw_spi_report_t *out);

typedef enum {
    FW_HV_NONE,        /* no hypervisor seen */
    FW_HV_ANNOUNCED,   /* a hypervisor says so (VirtualBox, KVM, ...): normal inside a VM */
    FW_HV_HIDDEN       /* none announced, yet CPUID is as slow as a VM exit: possible hidden hypervisor */
} fw_hv_state_t;

#define FW_HV_SLOW_TICKS 1000u   /* median TSC ticks per CPUID; bare metal stays well under, a VM exit goes over */

typedef struct {
    bool hv_bit;               /* CPUID.1:ECX[31] */
    char vendor[13];           /* CPUID 0x40000000 signature, "" if none */
    char sys_type[32];         /* /sys/hypervisor/type, "" if absent */
    uint32_t cpuid_ticks;      /* median TSC ticks per CPUID, 0 = not measured (not x86) */
} fw_hv_report_t;

/**
 * @brief Look for a hypervisor under Booto: the CPUID hypervisor bit and vendor, /sys/hypervisor/type,
 *        and how long CPUID takes (it always exits to a VT-x/AMD-V hypervisor). Read-only, about 0.1 s.
 *        A hypervisor can fake all of this, so a clean result proves nothing.
 * @param sys_type_path NULL = /sys/hypervisor/type.
 * @return BOOTO_OK; BOOTO_ERR_INVALID_ARG if out is NULL.
 */
booto_error_t firmware_hv_probe(const char *sys_type_path, fw_hv_report_t *out);
fw_hv_state_t firmware_hv_classify(const fw_hv_report_t *r);

const char *firmware_check_name(fw_check_id_t id);
const char *firmware_result_str(fw_result_t r);   /* "pass" "fail" "unknown" "n/a" */

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_FIRMWARE_AUDITOR_H */
