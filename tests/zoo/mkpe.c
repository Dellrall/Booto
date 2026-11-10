/**
 * @file mkpe.c
 * @brief Zoo fixture writer: mkpe signed|tampered|unsigned <out>. A harmless 1 KiB PE, never real boot code.
 */
#include "../pe_fixture.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s signed|tampered|unsigned <out>\n", argv[0]);
        return 2;
    }
    uint8_t b[0x1000];
    size_t len = strcmp(argv[1], "unsigned") == 0 ? build_pe(b, sizeof(b), true, false) : sign_pe(b, sizeof(b));
    if (strcmp(argv[1], "tampered") == 0) b[0x200] ^= 0xFF;   // one section byte patched after signing
    FILE *fp = len ? fopen(argv[2], "wb") : NULL;
    if (!fp || fwrite(b, 1, len, fp) != len || fclose(fp) != 0) {
        fprintf(stderr, "mkpe: cannot write %s\n", argv[2]);
        return 1;
    }
    return 0;
}
