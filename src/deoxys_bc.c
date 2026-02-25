/**
 * Deoxys-BC - AES-based tweakable block cipher
 * TWEAKEY framework, AES round function (S-box, ShiftRows, MixColumns)
 */
#include "deoxys_bc.h"
#include <string.h>

/* AES S-box (FIPS-197) */
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* h permutation: 0->1, 1->6, 2->11, 3->12, 4->5, 5->10, 6->15, 7->0, ... */
static const uint8_t H_PERM[16] = { 1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8 };

/* Round constants (Deoxys spec, 17 rounds) */
#define RC(v) { 1,2,4,8,(v),(v),(v),(v),0,0,0,0,0,0,0,0 }
static const uint8_t RCON[17][16] = {
    RC(0x2f), RC(0x5e), RC(0xbc), RC(0x63), RC(0xc6), RC(0x97), RC(0x35), RC(0x6a),
    RC(0xd4), RC(0xb3), RC(0x7d), RC(0xfa), RC(0xef), RC(0xc5), RC(0x91), RC(0x39),
    RC(0x72)
};

static inline uint8_t gf_mul2(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}
static inline uint8_t gf_mul3(uint8_t x) {
    return gf_mul2(x) ^ x;
}
static inline uint8_t gf_mul9(uint8_t x) {
    return gf_mul2(gf_mul2(gf_mul2(x))) ^ x;
}
static inline uint8_t gf_mul11(uint8_t x) {
    uint8_t x2 = gf_mul2(x);
    return gf_mul2(gf_mul2(x2)) ^ x2 ^ x;
}
static inline uint8_t gf_mul13(uint8_t x) {
    uint8_t x2 = gf_mul2(x);
    return gf_mul2(gf_mul2(x ^ x2)) ^ x;
}
static inline uint8_t gf_mul14(uint8_t x) {
    uint8_t x2 = gf_mul2(x), x4 = gf_mul2(x2), x8 = gf_mul2(x4);
    return x8 ^ x4 ^ x2;
}

static void h_perm(uint8_t tk[16]) {
    uint8_t tmp[16];
    int i;
    for (i = 0; i < 16; i++) tmp[i] = tk[H_PERM[i]];
    memcpy(tk, tmp, 16);
}

/* LFSR2: (x7||...||x0) -> (x6||...||x0||x7^x5) - per byte, left shift */
static void lfsr2(uint8_t tk[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        uint8_t b = tk[i];
        uint8_t fb = (uint8_t)(((b >> 7) ^ (b >> 5)) & 1);
        tk[i] = (uint8_t)((b << 1) | fb);
    }
}

/* LFSR3: (x7||...||x0) -> (x0^x6||x7||...||x1) - per byte, right shift */
static void lfsr3(uint8_t tk[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        uint8_t b = tk[i];
        uint8_t fb = (uint8_t)(((b << 7) ^ (b << 1)) & 0x80);
        tk[i] = (uint8_t)((b >> 1) | fb);
    }
}

static void sub_bytes(uint8_t *s) {
    int i;
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

static void shift_rows(uint8_t *s) {
    uint8_t t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13];  s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[15]; s[15] = s[11]; s[11] = s[7];  s[7] = t;
}

static void mix_columns(uint8_t *s) {
    uint8_t t[4];
    int i;
    for (i = 0; i < 4; i++) {
        t[0] = gf_mul2(s[i]) ^ gf_mul3(s[4+i]) ^ s[8+i] ^ s[12+i];
        t[1] = s[i] ^ gf_mul2(s[4+i]) ^ gf_mul3(s[8+i]) ^ s[12+i];
        t[2] = s[i] ^ s[4+i] ^ gf_mul2(s[8+i]) ^ gf_mul3(s[12+i]);
        t[3] = gf_mul3(s[i]) ^ s[4+i] ^ s[8+i] ^ gf_mul2(s[12+i]);
        s[i] = t[0]; s[4+i] = t[1]; s[8+i] = t[2]; s[12+i] = t[3];
    }
}

static void add_round_key(uint8_t *s, const uint8_t *rk) {
    int i;
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void inv_sub_bytes(uint8_t *s) {
    int i;
    for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
}
static void inv_shift_rows(uint8_t *s) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[7];  s[7] = s[11]; s[11] = s[15]; s[15] = s[3]; s[3] = t;
}
static void inv_mix_columns(uint8_t *s) {
    uint8_t t[4];
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t c0 = s[i], c1 = s[4+i], c2 = s[8+i], c3 = s[12+i];
        t[0] = gf_mul14(c0) ^ gf_mul11(c1) ^ gf_mul13(c2) ^ gf_mul9(c3);
        t[1] = gf_mul9(c0)  ^ gf_mul14(c1) ^ gf_mul11(c2) ^ gf_mul13(c3);
        t[2] = gf_mul13(c0) ^ gf_mul9(c1)  ^ gf_mul14(c2) ^ gf_mul11(c3);
        t[3] = gf_mul11(c0) ^ gf_mul13(c1) ^ gf_mul9(c2)  ^ gf_mul14(c3);
        s[i] = t[0]; s[4+i] = t[1]; s[8+i] = t[2]; s[12+i] = t[3];
    }
}

static void bc_encrypt_blocks(uint8_t *state, const uint8_t (*keys)[16], int rounds) {
    int r;
    add_round_key(state, keys[0]);
    for (r = 1; r < rounds; r++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, keys[r]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, keys[rounds]);
}

/* Deoxys-BC-256: tweakey = K (16) || T (16). K into TK2, T into TK1. */
void deoxys_bc_256_encrypt(const uint8_t tweakey[32], const uint8_t plaintext[16],
                           uint8_t ciphertext[16]) {
    uint8_t tk1[16], tk2[16], stk[17][16];
    int r;

    memcpy(tk2, tweakey, 16);        /* TK2_0 = K */
    memcpy(tk1, tweakey + 16, 16);   /* TK1_0 = T */

    for (r = 0; r <= 14; r++) {
        int i;
        for (i = 0; i < 16; i++)
            stk[r][i] = (uint8_t)(tk1[i] ^ tk2[i] ^ RCON[r][i]);
        if (r < 14) {
            h_perm(tk1);
            h_perm(tk2);
            lfsr2(tk2);
        }
    }

    memcpy(ciphertext, plaintext, 16);
    bc_encrypt_blocks(ciphertext, stk, 14);
}

static void bc_decrypt_blocks(uint8_t *state, const uint8_t (*keys)[16], int rounds) {
    int r;
    add_round_key(state, keys[rounds]);
    for (r = rounds - 1; r > 0; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, keys[r]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, keys[0]);
}

void deoxys_bc_256_decrypt(const uint8_t tweakey[32], const uint8_t ciphertext[16],
                           uint8_t plaintext[16]) {
    uint8_t tk1[16], tk2[16], stk[17][16];
    int r;

    memcpy(tk2, tweakey, 16);
    memcpy(tk1, tweakey + 16, 16);
    for (r = 0; r <= 14; r++) {
        int i;
        for (i = 0; i < 16; i++)
            stk[r][i] = (uint8_t)(tk1[i] ^ tk2[i] ^ RCON[r][i]);
        if (r < 14) {
            h_perm(tk1);
            h_perm(tk2);
            lfsr2(tk2);
        }
    }
    memcpy(plaintext, ciphertext, 16);
    bc_decrypt_blocks(plaintext, stk, 14);
}

void deoxys_bc_384_decrypt(const uint8_t tweakey[48], const uint8_t ciphertext[16],
                           uint8_t plaintext[16]) {
    uint8_t tk1[16], tk2[16], tk3[16], stk[17][16];
    int r;

    memcpy(tk3, tweakey, 16);
    memcpy(tk2, tweakey + 16, 16);
    memcpy(tk1, tweakey + 32, 16);
    for (r = 0; r <= 16; r++) {
        int i;
        for (i = 0; i < 16; i++)
            stk[r][i] = (uint8_t)(tk1[i] ^ tk2[i] ^ tk3[i] ^ RCON[r][i]);
        if (r < 16) {
            h_perm(tk1);
            h_perm(tk2);
            lfsr2(tk2);
            h_perm(tk3);
            lfsr3(tk3);
        }
    }
    memcpy(plaintext, ciphertext, 16);
    bc_decrypt_blocks(plaintext, stk, 16);
}

/* Deoxys-BC-384: tweakey = K (32) || T (16). W3=K[0..16], W2=K[16..32], W1=T. */
void deoxys_bc_384_encrypt(const uint8_t tweakey[48], const uint8_t plaintext[16],
                           uint8_t ciphertext[16]) {
    uint8_t tk1[16], tk2[16], tk3[16], stk[17][16];
    int r;

    memcpy(tk3, tweakey, 16);         /* TK3_0 = K[0..16] */
    memcpy(tk2, tweakey + 16, 16);    /* TK2_0 = K[16..32] */
    memcpy(tk1, tweakey + 32, 16);    /* TK1_0 = T */

    for (r = 0; r <= 16; r++) {
        int i;
        for (i = 0; i < 16; i++)
            stk[r][i] = (uint8_t)(tk1[i] ^ tk2[i] ^ tk3[i] ^ RCON[r][i]);
        if (r < 16) {
            h_perm(tk1);
            h_perm(tk2);
            lfsr2(tk2);
            h_perm(tk3);
            lfsr3(tk3);
        }
    }

    memcpy(ciphertext, plaintext, 16);
    bc_encrypt_blocks(ciphertext, stk, 16);
}
