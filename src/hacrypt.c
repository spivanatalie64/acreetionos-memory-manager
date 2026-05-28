/*
 * hacrypt — AcreetionOS heap encryption tool
 *
 * Encrypts/decrypts heap metadata using the same XOR scheme as ACalloc.
 * Used for forensics and heap analysis.
 *
 * Usage: hacrypt <key_hex> <file>
 *   Reads file, XORs with key, writes to stdout.
 *
 * For memory dumps:
 *   hacrypt $(acalloc-key) /proc/$(pid)/mem
 */

#include "acalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <key_hex> [file]\n", argv[0]);
        fprintf(stderr, "XOR a file/buffer with a 64-bit key.\n");
        fprintf(stderr, "If no file, reads from stdin.\n");
        return 1;
    }

    uint64_t key = strtoull(argv[1], NULL, 16);
    FILE *f = stdin;
    if (argc > 2) {
        f = fopen(argv[2], "rb");
        if (!f) { perror("fopen"); return 1; }
    }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ac_xor_buf(buf, n, key);
        fwrite(buf, 1, n, stdout);
    }

    if (f != stdin) fclose(f);
    return 0;
}
