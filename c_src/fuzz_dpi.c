/*
 * Memory-safety fuzz harness for dpi.c. Build with ASan + UBSan (see Makefile
 * target `fuzz`). Every buffer is heap-allocated at its EXACT length, so any
 * read past the end is reported by AddressSanitizer.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dpi.c"

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rng(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

int main(int argc, char **argv) {
    long iterations = argc > 1 ? atol(argv[1]) : 200000;
    if (argc > 2) rng_state ^= (uint64_t)atoll(argv[2]) * 0x2545F4914F6CDD1DULL;
    long matches = 0;

    /* API edge cases */
    if (inspect_payload_index(NULL, 10) != -1) return 1;
    if (inspect_payload_index("x", 0) != -1) return 1;
    if (inspect_payload_index("x", -5) != -1) return 1;
    if (inspect_batch(NULL, NULL, 5, NULL) != 0) return 1;
    if (signature_name(-1) != NULL || signature_name(NUM_SIGNATURES) != NULL) return 1;

    for (long it = 0; it < iterations; it++) {
        /* bias toward tiny buffers: boundary bugs live there */
        size_t len = (rng() % 4 == 0) ? rng() % 16 : rng() % 1500;
        unsigned char *buf = (unsigned char *)malloc(len ? len : 1);
        if (!buf) return 2;
        for (size_t i = 0; i < len; i++) buf[i] = (unsigned char)rng();

        /* plant a (possibly truncated, possibly upper-cased) signature,
           sometimes flush against the end of the buffer */
        if (len > 0 && rng() % 2) {
            const Signature *s = &SIGNATURES[rng() % NUM_SIGNATURES];
            size_t n = s->len - (rng() % 3 == 0 ? 1 : 0);
            if (n > len) n = len;
            size_t pos = (rng() % 2) ? len - n : (len - n) ? rng() % (len - n + 1) : 0;
            for (size_t k = 0; k < n; k++) {
                unsigned char c = (unsigned char)s->pattern[k];
                if (rng() % 2 && c >= 'a' && c <= 'z') c = (unsigned char)(c - 32);
                buf[pos + k] = c;
            }
        }
        if (inspect_payload_index((const char *)buf, (int)len) >= 0) matches++;

        /* batch API over exact-size buffers */
        const char *ptrs[1] = { (const char *)buf };
        int lens[1] = { (int)len };
        int res[1] = { -1 };
        inspect_batch(ptrs, lens, 1, res);
        free(buf);
    }
    printf("fuzz ok: %ld iterations, %ld buffers matched, no memory errors\n", iterations, matches);
    return 0;
}
