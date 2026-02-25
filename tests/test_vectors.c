/**
 * AES-IGE-AEAD Comprehensive Test Suite
 * Verifies all components and full algorithm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "aes.h"
#include "aes_ige.h"
#include "gf128.h"
#include "poly_mac.h"
#include "aes_ige_aead.h"
#include "chacha20_poly1305.h"
#include "deoxys.h"

#define TEST(name) do { \
    int _r = name(); \
    if (_r) { printf("%s FAILED\n", #name); failed++; } \
    else   { printf("%s PASSED\n", #name); } \
} while(0)

/* --- SHA-256 --- */
static int test_sha256(void) {
    const uint8_t msg[] = "abc";
    uint8_t digest[32];
    const uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    sha256(msg, 3, digest);
    return memcmp(digest, expected, 32) != 0;
}

/* --- AES-IGE raw blocks --- */
static int test_aes_ige_raw_blocks(void) {
    const uint8_t key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    const uint8_t iv[32]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    const uint8_t pt[32] = {0};
    uint8_t ct[32], dec[32];
    aes_ctx_t ctx;
    aes_init(&ctx, key);
    aes_ige_encrypt_blocks(&ctx, iv, pt, ct, 2);
    aes_ige_decrypt_blocks(&ctx, iv, ct, dec, 2);
    return memcmp(dec, pt, 32) != 0;
}

/* --- AES-IGE with padding --- */
static int test_aes_ige_padded(void) {
    uint8_t key[32], iv[32];
    const uint8_t pt[32]  = {0};
    uint8_t ct[64], dec[64];
    int clen, plen;
    memset(key, 0x11, 32);
    memset(iv, 0x22, 32);
    clen = aes_ige_encrypt(key, 32, iv, pt, 32, ct);
    if (clen != 48) return 1;
    plen = aes_ige_decrypt(key, 32, iv, ct, clen, dec);
    return (plen != 32 || memcmp(dec, pt, 32) != 0);
}

/* --- AEAD roundtrip: various lengths --- */
static int test_aead_lengths(void) {
    uint8_t key[32], iv[32], *ct, *pt_enc, *pt_dec;
    size_t pt_lens[] = {0, 1, 15, 16, 17, 32, 100, 256};
    int i, clen, plen;
    size_t max_ct = aes_ige_aead_encrypt_size(256);
    memset(key, 0xaa, 32);
    memset(iv, 0xbb, 32);
    ct = (uint8_t *)malloc(max_ct);
    pt_enc = (uint8_t *)malloc(256);
    pt_dec = (uint8_t *)malloc(256);
    if (!ct || !pt_enc || !pt_dec) { free(ct); free(pt_enc); free(pt_dec); return 1; }
    for (i = 0; i < (int)(sizeof(pt_lens)/sizeof(pt_lens[0])); i++) {
        size_t len = pt_lens[i];
        if (len > 0) memset(pt_enc, 0xcc, len);
        clen = aes_ige_aead_encrypt(key, iv, NULL, 0, len ? pt_enc : NULL, len, ct);
        if (clen < 0) { free(ct); free(pt_enc); free(pt_dec); return 1; }
        plen = aes_ige_aead_decrypt(key, NULL, 0, ct, (size_t)clen, pt_dec);
        if (plen < 0 || (size_t)plen != len) {
            free(ct); free(pt_enc); free(pt_dec); return 1;
        }
        if (len > 0 && memcmp(pt_enc, pt_dec, len) != 0) {
            free(ct); free(pt_enc); free(pt_dec); return 1;
        }
    }
    free(ct); free(pt_enc); free(pt_dec);
    return 0;
}

/* --- AEAD with AAD --- */
static int test_aead_with_aad(void) {
    uint8_t key[32], iv[32], ct[256], pt[128];
    const char *plain = "Secret message";
    const char *aad = "header: v1";
    int clen, plen;
    memset(key, 1, 32);
    memset(iv, 2, 32);
    clen = aes_ige_aead_encrypt(key, iv, (const uint8_t *)aad, strlen(aad), (const uint8_t *)plain, strlen(plain), ct);
    if (clen < 0) return 1;
    plen = aes_ige_aead_decrypt(key, (const uint8_t *)aad, strlen(aad), ct, (size_t)clen, pt);
    return (plen != (int)strlen(plain) || memcmp(pt, plain, strlen(plain)) != 0);
}

/* --- AEAD auth failure: tampered tag --- */
static int test_aead_auth_fail_tag(void) {
    uint8_t key[32], iv[32], ct[128], pt[64];
    memset(key, 0, 32);
    memset(iv, 1, 32);
    int clen = aes_ige_aead_encrypt(key, iv, NULL, 0, (const uint8_t *)"x", 1, ct);
    if (clen < 0) return 1;
    ct[clen - 1] ^= 1;
    int plen = aes_ige_aead_decrypt(key, NULL, 0, ct, (size_t)clen, pt);
    return plen >= 0;  /* must fail */
}

/* --- AEAD auth failure: wrong AAD --- */
static int test_aead_auth_fail_aad(void) {
    uint8_t key[32], iv[32], ct[128], pt[64];
    memset(key, 0, 32);
    memset(iv, 1, 32);
    int clen = aes_ige_aead_encrypt(key, iv, (const uint8_t *)"aad1", 4, (const uint8_t *)"data", 4, ct);
    if (clen < 0) return 1;
    int plen = aes_ige_aead_decrypt(key, (const uint8_t *)"aad2", 4, ct, (size_t)clen, pt);
    return plen >= 0;
}

/* --- AEAD auth failure: wrong key --- */
static int test_chacha20_poly1305_roundtrip(void) {
    uint8_t key[32], nonce[12], ct[256], pt[128];
    const uint8_t plain[] = "ChaCha20-Poly1305";
    int clen, plen;
    memset(key, 0x11, 32);
    memset(nonce, 0x22, 12);
    clen = chacha20_poly1305_encrypt(key, nonce, NULL, 0, plain, 17, ct);
    if (clen != 12 + 17 + 16) return 1;
    plen = chacha20_poly1305_decrypt(key, NULL, 0, ct, (size_t)clen, pt);
    return (plen != 17 || memcmp(pt, plain, 17) != 0);
}

static int test_chacha20_poly1305_auth_fail(void) {
    uint8_t key[32], nonce[12], ct[128], pt[64];
    memset(key, 0, 32);
    memset(nonce, 1, 12);
    int clen = chacha20_poly1305_encrypt(key, nonce, NULL, 0, (const uint8_t *)"x", 1, ct);
    if (clen < 0) return 1;
    ct[clen - 1] ^= 1;
    int plen = chacha20_poly1305_decrypt(key, NULL, 0, ct, (size_t)clen, pt);
    return plen >= 0;
}

/* Deoxys-I-128 - roundtrip */
static int test_deoxys_i_128(void) {
    const uint8_t key[16] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    const uint8_t nonce[8] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27};
    const uint8_t plaintext[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    uint8_t ct[64], pt[64];
    int clen, plen;
    clen = deoxys_i_128_encrypt(key, nonce, NULL, 0, plaintext, 32, ct);
    if (clen != 48) return 1;
    plen = deoxys_i_128_decrypt(key, nonce, NULL, 0, ct, clen, pt);
    if (plen != 32 || memcmp(pt, plaintext, 32) != 0) return 1;
    return 0;
}

/* Deoxys-I-256 - roundtrip */
static int test_deoxys_i_256(void) {
    uint8_t key[32], nonce[8], plaintext[64], ct[96], pt[96];
    int clen, plen;
    memset(key, 0x11, 32);
    memset(nonce, 0x22, 8);
    memset(plaintext, 0x33, 64);
    clen = deoxys_i_256_encrypt(key, nonce, NULL, 0, plaintext, 64, ct);
    if (clen != 80) return 1;
    plen = deoxys_i_256_decrypt(key, nonce, NULL, 0, ct, clen, pt);
    if (plen != 64 || memcmp(pt, plaintext, 64) != 0) return 1;
    return 0;
}

/* Deoxys-II-128 - roundtrip */
static int test_deoxys_ii_128(void) {
    uint8_t key[16], nonce[15], plaintext[64], ct[96], pt[96];
    int clen, plen;
    memset(key, 0x11, 16);
    memset(nonce, 0x22, 15);
    memset(plaintext, 0x33, 32);
    clen = deoxys_ii_128_encrypt(key, nonce, NULL, 0, plaintext, 32, ct);
    if (clen != 48) return 1;
    plen = deoxys_ii_128_decrypt(key, nonce, NULL, 0, ct, clen, pt);
    return (plen != 32 || memcmp(pt, plaintext, 32) != 0);
}

/* Deoxys-II-256 - roundtrip */
static int test_deoxys_ii_256(void) {
    uint8_t key[32], nonce[15], plaintext[33], ct[64], pt[64];
    int clen, plen;
    memset(key, 0x11, 32);
    memset(nonce, 0x22, 15);
    memset(plaintext, 0x33, 33);
    clen = deoxys_ii_256_encrypt(key, nonce, NULL, 0, plaintext, 33, ct);
    if (clen != 49) return 1;
    plen = deoxys_ii_256_decrypt(key, nonce, NULL, 0, ct, clen, pt);
    if (plen != 33 || memcmp(pt, plaintext, 33) != 0) return 1;
    return 0;
}

static int test_aead_auth_fail_key(void) {
    uint8_t key1[32], key2[32], iv[32], ct[128], pt[64];
    memset(key1, 1, 32);
    memset(key2, 2, 32);
    memset(iv, 0, 32);
    int clen = aes_ige_aead_encrypt(key1, iv, NULL, 0, (const uint8_t *)"x", 1, ct);
    if (clen < 0) return 1;
    int plen = aes_ige_aead_decrypt(key2, NULL, 0, ct, (size_t)clen, pt);
    return plen >= 0;
}

/* --- Buffer size helpers --- */
static int test_buffer_sizes(void) {
    if (aes_ige_aead_encrypt_size(0)   != 64) return 1;   /* IV + 16 padded + Tag */
    if (aes_ige_aead_encrypt_size(1)  != 64) return 1;
    if (aes_ige_aead_encrypt_size(16) != 80) return 1;   /* IV + 32 padded + Tag */
    if (aes_ige_aead_encrypt_size(17) != 80) return 1;
    if (aes_ige_aead_decrypt_size(48) != 0) return 1;   /* too short (< overhead) */
    if (aes_ige_aead_decrypt_size(64) != 16) return 1;   /* max PT from min CT */
    return 0;
}

/* --- Empty plaintext --- */
static int test_aead_empty_plaintext(void) {
    uint8_t key[32], iv[32], ct[128], pt[16];
    memset(key, 0, 32);
    memset(iv, 1, 32);
    int clen = aes_ige_aead_encrypt(key, iv, NULL, 0, NULL, 0, ct);
    if (clen != 64) return 1;  /* IV + 16 padded + Tag */
    int plen = aes_ige_aead_decrypt(key, NULL, 0, ct, (size_t)clen, pt);
    return plen != 0;
}

int main(void) {
    int failed = 0;
    printf("AES-IGE-AEAD Test Suite\n");
    printf("=======================\n");
    TEST(test_sha256);
    TEST(test_aes_ige_raw_blocks);
    TEST(test_aes_ige_padded);
    TEST(test_buffer_sizes);
    TEST(test_aead_lengths);
    TEST(test_aead_with_aad);
    TEST(test_aead_empty_plaintext);
    TEST(test_aead_auth_fail_tag);
    TEST(test_aead_auth_fail_aad);
    TEST(test_aead_auth_fail_key);
    TEST(test_chacha20_poly1305_roundtrip);
    TEST(test_chacha20_poly1305_auth_fail);
    TEST(test_deoxys_i_128);
    TEST(test_deoxys_i_256);
    TEST(test_deoxys_ii_128);
    TEST(test_deoxys_ii_256);
    printf("=======================\n");
    printf("%s: %d failed\n", failed ? "FAIL" : "PASS", failed);
    return failed ? 1 : 0;
}
