/**
 * @file authenticode.c
 * @brief Authenticode (PKCS#7 SignedData in the PE certificate table) verification via libcrypto.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "uefi_analyzer.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define SPC_INDIRECT_DATA_OID "1.3.6.1.4.1.311.2.1.4"

static bool oid_is(const ASN1_OBJECT *obj, const char *dotted) {
    char txt[64];
    return obj && OBJ_obj2txt(txt, sizeof(txt), obj, 1) > 0 && strcmp(txt, dotted) == 0;
}

/* Read one DER header at *p within [*p, end); returns the content length or -1. Advances *p past the header. */
static long der_header(const unsigned char **p, const unsigned char *end) {
    long len;
    int tag, cls;
    if (*p >= end) return -1;
    if (ASN1_get_object(p, &len, &tag, &cls, end - *p) & 0x80) return -1;
    return len <= end - *p ? len : -1;
}

/* Find the signed SpcIndirectDataContent body and the DigestInfo inside it. */
static authenticode_state_t check_p7(PKCS7 *p7, const pe_efi_info_t *info) {
    if (!PKCS7_type_is_signed(p7) || !p7->d.sign || !p7->d.sign->contents) return AUTHENTICODE_INVALID;
    PKCS7 *inner = p7->d.sign->contents;
    if (!oid_is(inner->type, SPC_INDIRECT_DATA_OID) || !inner->d.other ||
        inner->d.other->type != V_ASN1_SEQUENCE) {
        return AUTHENTICODE_INVALID;
    }
    const ASN1_STRING *seq = inner->d.other->value.sequence;
    const unsigned char *p = ASN1_STRING_get0_data(seq), *end = p + ASN1_STRING_length(seq);

    // The signature covers the SpcIndirectDataContent value without its outer SEQUENCE header.
    long body_len = der_header(&p, end);
    if (body_len < 0) return AUTHENTICODE_INVALID;
    const unsigned char *body = p;
    end = body + body_len;

    long skip = der_header(&p, end);           // SpcAttributeTypeAndOptionalValue
    if (skip < 0) return AUTHENTICODE_INVALID;
    p += skip;
    if (der_header(&p, end) < 0) return AUTHENTICODE_INVALID; // DigestInfo
    X509_ALGOR *alg = d2i_X509_ALGOR(NULL, &p, end - p);
    ASN1_OCTET_STRING *digest = alg ? d2i_ASN1_OCTET_STRING(NULL, &p, end - p) : NULL;

    authenticode_state_t state = AUTHENTICODE_INVALID;
    BIO *in = digest ? BIO_new_mem_buf(body, (int)body_len) : NULL;
    // NOVERIFY: integrity of the signature only; trust in the signer is the db audit's job.
    if (in && PKCS7_verify(p7, NULL, NULL, in, NULL, PKCS7_NOVERIFY | PKCS7_BINARY) == 1) {
        const ASN1_OBJECT *alg_oid;
        X509_ALGOR_get0(&alg_oid, NULL, NULL, alg);
        if (OBJ_obj2nid(alg_oid) != NID_sha256 || ASN1_STRING_length(digest) != 32) {
            state = AUTHENTICODE_UNSUPPORTED; // shortcut: SHA-1/SHA-384 signed images are not re-hashed; add if seen in the wild
        } else {
            char hex[65];
            const unsigned char *d = ASN1_STRING_get0_data(digest);
            for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", d[i]);
            state = strcasecmp(hex, info->authenticode_sha256) == 0 ? AUTHENTICODE_VALID : AUTHENTICODE_HASH_MISMATCH;
        }
    }
    BIO_free(in);
    ASN1_OCTET_STRING_free(digest);
    X509_ALGOR_free(alg);
    return state;
}

void authenticode_verify(const uint8_t *buf, size_t len, pe_efi_info_t *info) {
    if (!buf || !info) return;
    info->authenticode_state = AUTHENTICODE_NONE;
    if (!info->has_authenticode) return; // parser already bounds-checked the table against len
    (void)len;

    info->authenticode_state = AUTHENTICODE_INVALID;
    if (info->cert_table_size < 8) return;
    // shortcut: only the first WIN_CERTIFICATE is checked; dual-signed images carry the rest as nested signatures
    const uint8_t *wc = buf + info->cert_table_rva;
    uint32_t dw_len = (uint32_t)wc[0] | ((uint32_t)wc[1] << 8) | ((uint32_t)wc[2] << 16) | ((uint32_t)wc[3] << 24);
    uint16_t cert_type = (uint16_t)(wc[6] | (wc[7] << 8));
    if (dw_len < 8 || dw_len > info->cert_table_size ||
        cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
        return;
    }

    const unsigned char *der = wc + 8;
    PKCS7 *p7 = d2i_PKCS7(NULL, &der, (long)(dw_len - 8));
    if (p7) info->authenticode_state = check_p7(p7, info);
    PKCS7_free(p7);
    ERR_clear_error();
}
