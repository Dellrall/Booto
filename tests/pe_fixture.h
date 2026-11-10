/**
 * @file pe_fixture.h
 * @brief Synthetic PE images for tests and the zoo: unsigned, garbage-signed, or really Authenticode-signed.
 */
#ifndef BOOTO_PE_FIXTURE_H
#define BOOTO_PE_FIXTURE_H

#include "uefi_analyzer.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Build a 0x300-byte image (headers 0x200 + one 0x100 section); with_cert appends a 0x80 cert table at 0x300. */
static size_t build_pe(uint8_t *b, size_t cap, bool pe32_plus, bool with_cert) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    b[coff] = 0x64; b[coff + 1] = 0x86;
    b[coff + 2] = 1;                               // NumberOfSections
    b[coff + 16] = pe32_plus ? 0xF0 : 0xE0;        // SizeOfOptionalHeader
    b[opt] = 0x0b; b[opt + 1] = pe32_plus ? 0x02 : 0x01;
    b[opt + 60] = 0x00; b[opt + 61] = 0x02;        // SizeOfHeaders = 0x200
    b[opt + 64] = 0x11; b[opt + 65] = 0x22;        // CheckSum
    b[opt + 68] = 10;
    b[opt + (pe32_plus ? 108 : 92)] = 16;          // NumberOfRvaAndSizes
    size_t sect = opt + (pe32_plus ? 0xF0 : 0xE0);
    b[sect + 17] = 0x01;                           // SizeOfRawData = 0x100
    b[sect + 21] = 0x02;                           // PointerToRawData = 0x200
    for (size_t i = 0x200; i < 0x300; i++) b[i] = (uint8_t)i;
    if (!with_cert) return 0x300;
    size_t dir = opt + (pe32_plus ? 112 : 96) + 32;
    b[dir + 1] = 0x03;                             // cert table at file offset 0x300
    b[dir + 4] = 0x80;
    memset(b + 0x300, 0xC5, 0x80);
    return 0x380;
}

/* Sign build_pe's unsigned image the way signtool/sbsign does: SpcIndirectDataContent with the SHA-256
 * Authenticode digest, PKCS#7 SignedData by a throwaway self-signed key, appended as a WIN_CERTIFICATE. */
static size_t sign_pe(uint8_t *b, size_t cap) {
    size_t len = build_pe(b, cap, true, false);
    pe_efi_info_t info;
    if (uefi_parse_pe_buffer(b, len, &info) != BOOTO_OK) return 0;
    uint8_t idc[] = {
        0x30, 0x41,                                                       // SpcIndirectDataContent
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f, // SPC_PE_IMAGE_DATA
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0x04, 0x20,                                                       // sha256 digest follows
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(info.authenticode_sha256 + i * 2, "%2x", &v);
        idc[sizeof(idc) - 32 + (size_t)i] = (uint8_t)v;
    }

    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (const unsigned char *)"Booto Test", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());

    PKCS7 *p7 = PKCS7_new(), *inner = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_SIGNER_INFO *si = PKCS7_add_signature(p7, cert, key, EVP_sha256());
    PKCS7_add_certificate(p7, cert);
    ASN1_OBJECT *spc = OBJ_txt2obj("1.3.6.1.4.1.311.2.1.4", 1);
    PKCS7_add_attrib_content_type(si, OBJ_dup(spc));
    inner->type = spc;
    inner->d.other = ASN1_TYPE_new();
    ASN1_STRING *seq = ASN1_STRING_new();
    ASN1_STRING_set(seq, idc, sizeof(idc));
    ASN1_TYPE_set(inner->d.other, V_ASN1_SEQUENCE, seq);
    PKCS7_set_content(p7, inner);
    BIO *bio = PKCS7_dataInit(p7, NULL);
    BIO_write(bio, idc + 2, sizeof(idc) - 2);  // signed bytes exclude the outer SEQUENCE header
    PKCS7_dataFinal(p7, bio);
    BIO_free_all(bio);

    unsigned char *der = NULL;
    int der_len = i2d_PKCS7(p7, &der);
    size_t wc_len = 8 + (size_t)der_len, table = (wc_len + 7) & ~(size_t)7;
    if (der_len <= 0 || 0x300 + table > cap) table = 0;
    if (table) {
        uint8_t *wc = b + 0x300;
        memset(wc, 0, table);
        wc[0] = (uint8_t)wc_len; wc[1] = (uint8_t)(wc_len >> 8);
        wc[5] = 0x02;                              // WIN_CERT_REVISION_2_0
        wc[6] = 0x02;                              // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        memcpy(wc + 8, der, (size_t)der_len);
        size_t dir = 0x84 + 20 + 112 + 32;
        b[dir + 1] = 0x03;                         // cert table at file offset 0x300
        b[dir + 4] = (uint8_t)table; b[dir + 5] = (uint8_t)(table >> 8);
    }
    OPENSSL_free(der);
    PKCS7_free(p7);
    X509_free(cert);
    EVP_PKEY_free(key);
    return table ? 0x300 + table : 0;
}

#endif
