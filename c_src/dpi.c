#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

typedef struct {
    const char *pattern;   /* stored in lowercase; matching is ASCII case-insensitive */
    size_t len;
} Signature;

#define SIG(s) { s, sizeof(s) - 1 }

/*
 * Signature table. All patterns are lowercase because the matcher lowercases
 * the payload byte-by-byte (ASCII only) while comparing.
 *
 * Length rule of thumb: avoid substrings under ~6 bytes. Short signatures
 * match by chance inside binary data and cause false positives.
 *
 * This is the single source of truth: main.py and benchmark_dpi.py read the
 * names back through signature_count() / signature_name(), so there is no
 * second copy to keep in sync.
 */
static const Signature SIGNATURES[] = {
    SIG("' or '1'='1"),    /* SQLi: classic tautology        */
    SIG(" or 1=1"),        /* SQLi: numeric tautology        */
    SIG("union select"),   /* SQLi: UNION-based              */
    SIG("union all select"),
    SIG("<script"),        /* XSS: script tag (with/without attributes) */
    SIG("javascript:"),    /* XSS: URI scheme                */
    SIG("onerror="),       /* XSS: event handler             */
    SIG("../../"),         /* Path traversal (POSIX)         */
    SIG("..\\..\\"),       /* Path traversal (Windows)       */
    SIG("etc/passwd"),     /* Sensitive file access          */
    SIG("etc/shadow"),
    SIG("cmd.exe"),        /* Command injection (Windows)    */
    SIG("/bin/sh"),        /* Command injection (POSIX)      */
    SIG("; whoami"),       /* Command chaining               */
};

#define NUM_SIGNATURES ((int)(sizeof(SIGNATURES) / sizeof(SIGNATURES[0])))

static inline unsigned char to_lower_ascii(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

/*
 * Single-pass, ASCII case-insensitive multi-signature scan over a raw (not
 * NUL-terminated) buffer.
 *
 * A 256-entry table marks which bytes can START a signature, so most payload
 * bytes are rejected with one table lookup. Only candidate positions are
 * compared against the (few) signatures that share that first byte.
 *
 * Bounds: a signature is compared only if i + len <= payload_len, so the
 * highest byte ever read is index payload_len - 1.
 *
 * Returns the index of the signature that matches EARLIEST in the payload
 * (ties: lowest table index), or -1.
 */
EXPORT int inspect_payload_index(const char *payload, int payload_len) {
    if (!payload || payload_len <= 0) return -1;

    unsigned char is_first[256];
    memset(is_first, 0, sizeof(is_first));
    for (int s = 0; s < NUM_SIGNATURES; s++) {
        is_first[(unsigned char)SIGNATURES[s].pattern[0]] = 1;
    }

    const unsigned char *p = (const unsigned char *)payload;
    const size_t n = (size_t)payload_len;

    for (size_t i = 0; i < n; i++) {
        unsigned char c = to_lower_ascii(p[i]);
        if (!is_first[c]) continue;

        for (int s = 0; s < NUM_SIGNATURES; s++) {
            const Signature *sig = &SIGNATURES[s];
            if ((unsigned char)sig->pattern[0] != c || sig->len > n - i) continue;
            size_t j = 1;
            while (j < sig->len && to_lower_ascii(p[i + j]) == (unsigned char)sig->pattern[j]) j++;
            if (j == sig->len) return s;
        }
    }
    return -1;
}

EXPORT int inspect_payload(const char *payload, int payload_len) {
    return inspect_payload_index(payload, payload_len) >= 0 ? 1 : 0;
}

EXPORT int inspect_batch(const char **payloads, const int *lengths, int count, int *results) {
    if (!payloads || !lengths || !results || count <= 0) return 0;

    for (int i = 0; i < count; i++) {
        results[i] = inspect_payload(payloads[i], lengths[i]);
    }
    return 1;
}

/* Introspection helpers so callers never hard-code the signature list. */
EXPORT int signature_count(void) { return NUM_SIGNATURES; }

EXPORT const char *signature_name(int index) {
    if (index < 0 || index >= NUM_SIGNATURES) return NULL;
    return SIGNATURES[index].pattern;
}

EXPORT int max_signature_len(void) {
    size_t m = 0;
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        if (SIGNATURES[i].len > m) m = SIGNATURES[i].len;
    }
    return (int)m;
}
