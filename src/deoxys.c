/**
 * Deoxys-I and Deoxys-II AEAD modes
 * Based on CAESAR specification and RustCrypto reference
 */
#include "deoxys.h"
#include "deoxys_bc.h"
#include <stdlib.h>
#include <string.h>

#define BLOCK 16

/* Tweak domain separators */
#define TWEAK_AD      0x20
#define TWEAK_AD_LAST 0x60
#define TWEAK_M       0x00
#define TWEAK_M_LAST  0x40
#define TWEAK_TAG     0x10
#define TWEAK_CHKSUM  0x50

/* Build tweakey: K || T (16 bytes) for BC-256, or K || T for BC-384 */
static void build_tweak_256(uint8_t tweakey[32], const uint8_t key[16], const uint8_t tweak[16]) {
    memcpy(tweakey, key, 16);
    memcpy(tweakey + 16, tweak, 16);
}
static void build_tweak_384(uint8_t tweakey[48], const uint8_t key[32], const uint8_t tweak[16]) {
    memcpy(tweakey, key, 32);
    memcpy(tweakey + 32, tweak, 16);
}

/* Encode 8-byte nonce into tweak (Deoxys-I). Domain set separately per block. */
static void encode_nonce_i(uint8_t tweak[16], const uint8_t nonce[8]) {
    memset(tweak, 0, 16);
    tweak[0] = (uint8_t)(nonce[0] >> 4);
    tweak[1] = (uint8_t)((nonce[0] << 4) | (nonce[1] >> 4));
    tweak[2] = (uint8_t)((nonce[1] << 4) | (nonce[2] >> 4));
    tweak[3] = (uint8_t)((nonce[2] << 4) | (nonce[3] >> 4));
    tweak[4] = (uint8_t)((nonce[3] << 4) | (nonce[4] >> 4));
    tweak[5] = (uint8_t)((nonce[4] << 4) | (nonce[5] >> 4));
    tweak[6] = (uint8_t)((nonce[5] << 4) | (nonce[6] >> 4));
    tweak[7] = (uint8_t)((nonce[6] << 4) | (nonce[7] >> 4));
    tweak[8] = (uint8_t)(nonce[7] << 4);
}

/* Process AAD (common for Deoxys-I and Deoxys-II) */
static void process_ad_256(const uint8_t *aad, size_t aad_len, const uint8_t key[16],
                          uint8_t tag[16]) {
    uint8_t tweakey[32], tweak[16], block[16];
    size_t i, full_blocks;

    memset(tag, 0, 16);
    if (aad_len == 0) return;

    tweak[0] = TWEAK_AD;
    memset(tweak + 1, 0, 15);

    full_blocks = aad_len / 16;
    for (i = 0; i < full_blocks; i++) {
        uint64_t idx = (uint64_t)i;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memcpy(block, aad + i * 16, 16);
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }

    if (aad_len % 16) {
        size_t rem = aad_len % 16;
        uint64_t idx = (uint64_t)full_blocks;
        tweak[0] = TWEAK_AD_LAST;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memset(block, 0, 16);
        memcpy(block, aad + full_blocks * 16, rem);
        block[rem] = 0x80;
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }
}

static void process_ad_384(const uint8_t *aad, size_t aad_len, const uint8_t key[32],
                          uint8_t tag[16]) {
    uint8_t tweakey[48], tweak[16], block[16];
    size_t i, full_blocks;

    memset(tag, 0, 16);
    if (aad_len == 0) return;

    tweak[0] = TWEAK_AD;
    memset(tweak + 1, 0, 15);

    full_blocks = aad_len / 16;
    for (i = 0; i < full_blocks; i++) {
        uint64_t idx = (uint64_t)i;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memcpy(block, aad + i * 16, 16);
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }

    if (aad_len % 16) {
        size_t rem = aad_len % 16;
        uint64_t idx = (uint64_t)full_blocks;
        tweak[0] = TWEAK_AD_LAST;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memset(block, 0, 16);
        memcpy(block, aad + full_blocks * 16, rem);
        block[rem] = 0x80;
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }
}

/* --- Deoxys-I-128 --- */
int deoxys_i_128_encrypt(const uint8_t key[DEOXYS_I_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext) {
    uint8_t tweakey[32], tweak[16], block[16], tag[16], checksum[16];
    size_t i, full_blocks, rem;
    uint64_t idx;

    if (!key || !nonce || !ciphertext) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    memset(tag, 0, 16);
    memset(checksum, 0, 16);
    process_ad_256(aad, aad_len, key, tag);

    encode_nonce_i(tweak, nonce);
    tweak[0] = (tweak[0] & 0x0f) | TWEAK_M;
    full_blocks = plaintext_len / 16;
    rem = plaintext_len % 16;

    for (i = 0; i < full_blocks; i++) {
        uint8_t tmp;
        idx = (uint64_t)i;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memcpy(block, plaintext + i * 16, 16);
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];

        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        memcpy(ciphertext + i * 16, block, 16);
    }

    if (rem) {
        uint8_t tmp;
        idx = (uint64_t)full_blocks;
        tweak[0] = (tweak[0] & 0x0f) | TWEAK_M_LAST;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memset(block, 0, 16);
        memcpy(block, plaintext + full_blocks * 16, rem);
        block[rem] = 0x80;
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];

        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        for (i = 0; i < rem; i++) ciphertext[full_blocks * 16 + i] = block[i];
        full_blocks++;
    }

    /* Final tag */
    {
        uint8_t tmp = tweak[8] & 0xf0;
        idx = (uint64_t)full_blocks;
        tweak[0] = (tweak[0] & 0x0f) | (rem ? TWEAK_CHKSUM : TWEAK_TAG);
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
    tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
    tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, checksum, block);
        for (i = 0; i < 16; i++) tag[i] ^= block[i];
    }

    memcpy(ciphertext + ((plaintext_len + 15) / 16) * 16, tag, 16);
    return (int)(((plaintext_len + 15) / 16) * 16 + 16);
}

int deoxys_i_128_decrypt(const uint8_t key[DEOXYS_I_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext) {
    uint8_t tweakey[32], tweak[16], block[16], checksum[16], computed_tag[16];
    size_t i, full_blocks, pt_len;
    uint64_t idx;

    if (ciphertext_len < 16) return -1;
    if (!key || !nonce || !ciphertext || !plaintext) return -1;

    full_blocks = (ciphertext_len - 16) / 16;
    if (full_blocks * 16 + 16 != ciphertext_len) return -1;

    memset(computed_tag, 0, 16);
    memset(checksum, 0, 16);
    process_ad_256(aad, aad_len, key, computed_tag);

    encode_nonce_i(tweak, nonce);
    tweak[0] = (tweak[0] & 0x0f) | TWEAK_M;

    for (i = 0; i < full_blocks; i++) {
        uint8_t tmp;
        idx = (uint64_t)i;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memcpy(block, ciphertext + i * 16, 16);
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_decrypt(tweakey, block, block);
        memcpy(plaintext + i * 16, block, 16);
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];
    }

    /* Padding: 0x80 at position rem, rest zeros. Find 0x80 in last block */
    if (full_blocks == 0) {
        pt_len = 0;
        tweak[0] = (tweak[0] & 0x0f) | TWEAK_TAG;
    } else {
        uint8_t *last = plaintext + (full_blocks - 1) * 16;
        size_t j;
        for (j = 0; j < 16 && last[j] != 0x80; j++) ;
        if (j < 16) {
            pt_len = (full_blocks - 1) * 16 + j;
            tweak[0] = (tweak[0] & 0x0f) | TWEAK_CHKSUM;
        } else {
            pt_len = full_blocks * 16;
            tweak[0] = (tweak[0] & 0x0f) | TWEAK_TAG;
        }
    }
    {
        uint8_t tmp = tweak[8] & 0xf0;
        idx = (uint64_t)full_blocks;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, checksum, block);
        for (i = 0; i < 16; i++) computed_tag[i] ^= block[i];
    }

    if (memcmp(computed_tag, ciphertext + full_blocks * 16, 16) != 0) return -1;
    return (int)pt_len;
}

/* --- Deoxys-I-256 (Deoxys-BC-384, same mode as I-128) --- */
int deoxys_i_256_encrypt(const uint8_t key[DEOXYS_I_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext) {
    uint8_t tweakey[48], tweak[16], block[16], tag[16], checksum[16];
    size_t i, full_blocks, rem;
    uint64_t idx;

    if (!key || !nonce || !ciphertext) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    memset(tag, 0, 16);
    memset(checksum, 0, 16);
    process_ad_384(aad, aad_len, key, tag);

    encode_nonce_i(tweak, nonce);
    tweak[0] = (tweak[0] & 0x0f) | TWEAK_M;
    full_blocks = plaintext_len / 16;
    rem = plaintext_len % 16;

    for (i = 0; i < full_blocks; i++) {
        uint8_t tmp;
        idx = (uint64_t)i;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memcpy(block, plaintext + i * 16, 16);
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];

        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        memcpy(ciphertext + i * 16, block, 16);
    }

    if (rem) {
        uint8_t tmp;
        idx = (uint64_t)full_blocks;
        tweak[0] = (tweak[0] & 0x0f) | TWEAK_M_LAST;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memset(block, 0, 16);
        memcpy(block, plaintext + full_blocks * 16, rem);
        block[rem] = 0x80;
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];

        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        for (i = 0; i < rem; i++) ciphertext[full_blocks * 16 + i] = block[i];
        full_blocks++;
    }

    {
        uint8_t tmp = tweak[8] & 0xf0;
        idx = (uint64_t)full_blocks;
        tweak[0] = (tweak[0] & 0x0f) | (rem ? TWEAK_CHKSUM : TWEAK_TAG);
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, checksum, block);
        for (i = 0; i < 16; i++) tag[i] ^= block[i];
    }

    memcpy(ciphertext + ((plaintext_len + 15) / 16) * 16, tag, 16);
    return (int)(((plaintext_len + 15) / 16) * 16 + 16);
}

int deoxys_i_256_decrypt(const uint8_t key[DEOXYS_I_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext) {
    uint8_t tweakey[48], tweak[16], block[16], checksum[16], computed_tag[16];
    size_t i, full_blocks, pt_len;
    uint64_t idx;

    if (ciphertext_len < 16) return -1;
    if (!key || !nonce || !ciphertext || !plaintext) return -1;

    full_blocks = (ciphertext_len - 16) / 16;
    if (full_blocks * 16 + 16 != ciphertext_len) return -1;

    memset(computed_tag, 0, 16);
    memset(checksum, 0, 16);
    process_ad_384(aad, aad_len, key, computed_tag);

    encode_nonce_i(tweak, nonce);
    tweak[0] = (tweak[0] & 0x0f) | TWEAK_M;

    for (i = 0; i < full_blocks; i++) {
        uint8_t tmp;
        idx = (uint64_t)i;
        tmp = tweak[8] & 0xf0;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        memcpy(block, ciphertext + i * 16, 16);
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_decrypt(tweakey, block, block);
        memcpy(plaintext + i * 16, block, 16);
        for (idx = 0; idx < 16; idx++) checksum[idx] ^= block[idx];
    }

    if (full_blocks == 0) {
        pt_len = 0;
        tweak[0] = (tweak[0] & 0x0f) | TWEAK_TAG;
    } else {
        uint8_t *last = plaintext + (full_blocks - 1) * 16;
        size_t j;
        for (j = 0; j < 16 && last[j] != 0x80; j++) ;
        if (j < 16) {
            pt_len = (full_blocks - 1) * 16 + j;
            tweak[0] = (tweak[0] & 0x0f) | TWEAK_CHKSUM;
        } else {
            pt_len = full_blocks * 16;
            tweak[0] = (tweak[0] & 0x0f) | TWEAK_TAG;
        }
    }
    {
        uint8_t tmp = tweak[8] & 0xf0;
        idx = (uint64_t)full_blocks;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;
        tweak[8] = (tweak[8] & 0x0f) | tmp;

        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, checksum, block);
        for (i = 0; i < 16; i++) computed_tag[i] ^= block[i];
    }

    if (memcmp(computed_tag, ciphertext + full_blocks * 16, 16) != 0) return -1;
    return (int)pt_len;
}
/* Deoxys-II: authenticate message into tag (no nonce in tweak for this step) */
static void auth_message_256(const uint8_t *buf, size_t buf_len, const uint8_t key[16],
                             uint8_t tag[16]) {
    uint8_t tweakey[32], tweak[16], block[16];
    size_t i, full_blocks;

    if (buf_len == 0) return;

    tweak[0] = TWEAK_M;
    memset(tweak + 1, 0, 15);

    full_blocks = buf_len / 16;
    for (i = 0; i < full_blocks; i++) {
        uint64_t idx = (uint64_t)i;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memcpy(block, buf + i * 16, 16);
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }

    if (buf_len % 16) {
        size_t rem = buf_len % 16;
        uint64_t idx = (uint64_t)full_blocks;
        tweak[0] = TWEAK_M_LAST;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memset(block, 0, 16);
        memcpy(block, buf + full_blocks * 16, rem);
        block[rem] = 0x80;
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }
}

static void auth_message_384(const uint8_t *buf, size_t buf_len, const uint8_t key[32],
                             uint8_t tag[16]) {
    uint8_t tweakey[48], tweak[16], block[16];
    size_t i, full_blocks;

    if (buf_len == 0) return;

    tweak[0] = TWEAK_M;
    memset(tweak + 1, 0, 15);

    full_blocks = buf_len / 16;
    for (i = 0; i < full_blocks; i++) {
        uint64_t idx = (uint64_t)i;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memcpy(block, buf + i * 16, 16);
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }

    if (buf_len % 16) {
        size_t rem = buf_len % 16;
        uint64_t idx = (uint64_t)full_blocks;
        tweak[0] = TWEAK_M_LAST;
        tweak[8] = (uint8_t)(idx >> 56); tweak[9] = (uint8_t)(idx >> 48);
        tweak[10] = (uint8_t)(idx >> 40); tweak[11] = (uint8_t)(idx >> 32);
        tweak[12] = (uint8_t)(idx >> 24); tweak[13] = (uint8_t)(idx >> 16);
        tweak[14] = (uint8_t)(idx >> 8); tweak[15] = (uint8_t)idx;

        memset(block, 0, 16);
        memcpy(block, buf + full_blocks * 16, rem);
        block[rem] = 0x80;
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);
        { size_t j; for (j = 0; j < 16; j++) tag[j] ^= block[j]; }
    }
}

/* Store idx as big-endian in buf[0..8] */
static void u64_be(uint8_t buf[8], uint64_t idx) {
    buf[0] = (uint8_t)(idx >> 56);
    buf[1] = (uint8_t)(idx >> 48);
    buf[2] = (uint8_t)(idx >> 40);
    buf[3] = (uint8_t)(idx >> 32);
    buf[4] = (uint8_t)(idx >> 24);
    buf[5] = (uint8_t)(idx >> 16);
    buf[6] = (uint8_t)(idx >> 8);
    buf[7] = (uint8_t)idx;
}

/* Deoxys-II XOR encrypt/decrypt: tweak=tag|0x80, block=[0,nonce], XOR index in/out */
static void xor_message_256(const uint8_t *in, uint8_t *out, size_t len,
                            const uint8_t key[16], const uint8_t tag[16],
                            const uint8_t nonce[15]) {
    uint8_t tweakey[32], tweak[16], block[16], idx_be[8];
    size_t i, full_blocks, rem;
    uint64_t idx;

    if (len == 0) return;

    memcpy(tweak, tag, 16);
    tweak[0] |= 0x80;

    full_blocks = len / 16;
    rem = len % 16;

    for (i = 0; i < full_blocks; i++) {
        size_t j;
        idx = (uint64_t)i;
        u64_be(idx_be, idx);
        for (j = 0; j < 8; j++) tweak[8 + j] ^= idx_be[j];

        block[0] = 0;
        memcpy(block + 1, nonce, 15);
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);

        for (j = 0; j < 16; j++) out[i * 16 + j] = in[i * 16 + j] ^ block[j];

        for (j = 0; j < 8; j++) tweak[8 + j] ^= idx_be[j];
    }

    if (rem) {
        size_t j;
        idx = (uint64_t)full_blocks;
        u64_be(idx_be, idx);
        for (j = 0; j < 8; j++) tweak[8 + j] ^= idx_be[j];

        block[0] = 0;
        memcpy(block + 1, nonce, 15);
        build_tweak_256(tweakey, key, tweak);
        deoxys_bc_256_encrypt(tweakey, block, block);

        for (j = 0; j < rem; j++) out[full_blocks * 16 + j] = in[full_blocks * 16 + j] ^ block[j];
    }
}

static void xor_message_384(const uint8_t *in, uint8_t *out, size_t len,
                            const uint8_t key[32], const uint8_t tag[16],
                            const uint8_t nonce[15]) {
    uint8_t tweakey[48], tweak[16], block[16];
    size_t i, full_blocks, rem;
    uint64_t idx;

    if (len == 0) return;

    memcpy(tweak, tag, 16);
    tweak[0] |= 0x80;

    full_blocks = len / 16;
    rem = len % 16;

    for (i = 0; i < full_blocks; i++) {
        size_t j;
        idx = (uint64_t)i;
        for (j = 0; j < 8; j++) tweak[8 + j] ^= ((const uint8_t *)&idx)[7 - j];

        block[0] = 0;
        memcpy(block + 1, nonce, 15);
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);

        for (j = 0; j < 16; j++) out[i * 16 + j] = in[i * 16 + j] ^ block[j];

        for (j = 0; j < 8; j++) tweak[8 + j] ^= ((const uint8_t *)&idx)[7 - j];
    }

    if (rem) {
        size_t j;
        idx = (uint64_t)full_blocks;
        for (j = 0; j < 8; j++) tweak[8 + j] ^= ((const uint8_t *)&idx)[7 - j];

        block[0] = 0;
        memcpy(block + 1, nonce, 15);
        build_tweak_384(tweakey, key, tweak);
        deoxys_bc_384_encrypt(tweakey, block, block);

        for (j = 0; j < rem; j++)
            out[full_blocks * 16 + j] = in[full_blocks * 16 + j] ^ block[j];
    }
}

/* --- Deoxys-II-128 --- */
int deoxys_ii_128_encrypt(const uint8_t key[DEOXYS_II_128_KEY_SIZE],
                          const uint8_t nonce[DEOXYS_II_128_NONCE_SIZE],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext) {
    uint8_t tweakey[32], tweak[16], tag[16];

    if (!key || !nonce || !ciphertext) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    memset(tag, 0, 16);
    process_ad_256(aad, aad_len, key, tag);
    auth_message_256(plaintext, plaintext_len, key, tag);

    tweak[0] = TWEAK_TAG;
    memcpy(tweak + 1, nonce, 15);
    build_tweak_256(tweakey, key, tweak);
    deoxys_bc_256_encrypt(tweakey, tag, tag);

    xor_message_256(plaintext, ciphertext, plaintext_len, key, tag, nonce);

    memcpy(ciphertext + plaintext_len, tag, 16);
    return (int)(plaintext_len + 16);
}

int deoxys_ii_128_decrypt(const uint8_t key[DEOXYS_II_128_KEY_SIZE],
                          const uint8_t nonce[DEOXYS_II_128_NONCE_SIZE],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext) {
    uint8_t tweakey[32], tweak[16], tag[16], computed_tag[16];
    size_t ct_len;

    if (ciphertext_len < 16) return -1;
    if (!key || !nonce || !ciphertext || !plaintext) return -1;

    ct_len = ciphertext_len - 16;
    memcpy(tag, ciphertext + ct_len, 16);

    memset(computed_tag, 0, 16);
    process_ad_256(aad, aad_len, key, computed_tag);

    xor_message_256(ciphertext, plaintext, ct_len, key, tag, nonce);

    memset(tweak, 0, 16);
    auth_message_256(plaintext, ct_len, key, computed_tag);

    tweak[0] = TWEAK_TAG;
    memcpy(tweak + 1, nonce, 15);
    build_tweak_256(tweakey, key, tweak);
    deoxys_bc_256_encrypt(tweakey, computed_tag, computed_tag);

    if (memcmp(computed_tag, tag, 16) != 0) return -1;
    return (int)ct_len;
}

/* --- Deoxys-II-256 --- */
int deoxys_ii_256_encrypt(const uint8_t key[DEOXYS_II_256_KEY_SIZE],
                          const uint8_t nonce[DEOXYS_II_256_NONCE_SIZE],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext) {
    uint8_t tweakey[48], tweak[16], tag[16];

    if (!key || !nonce || !ciphertext) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    memset(tag, 0, 16);
    process_ad_384(aad, aad_len, key, tag);
    auth_message_384(plaintext, plaintext_len, key, tag);

    tweak[0] = TWEAK_TAG;
    memcpy(tweak + 1, nonce, 15);
    build_tweak_384(tweakey, key, tweak);
    deoxys_bc_384_encrypt(tweakey, tag, tag);

    xor_message_384(plaintext, ciphertext, plaintext_len, key, tag, nonce);

    memcpy(ciphertext + plaintext_len, tag, 16);
    return (int)(plaintext_len + 16);
}

int deoxys_ii_256_decrypt(const uint8_t key[DEOXYS_II_256_KEY_SIZE],
                          const uint8_t nonce[DEOXYS_II_256_NONCE_SIZE],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext) {
    uint8_t tweakey[48], tweak[16], tag[16], computed_tag[16];
    size_t ct_len;

    if (ciphertext_len < 16) return -1;
    if (!key || !nonce || !ciphertext || !plaintext) return -1;

    ct_len = ciphertext_len - 16;
    memcpy(tag, ciphertext + ct_len, 16);

    memset(computed_tag, 0, 16);
    process_ad_384(aad, aad_len, key, computed_tag);

    xor_message_384(ciphertext, plaintext, ct_len, key, tag, nonce);

    memset(tweak, 0, 16);
    auth_message_384(plaintext, ct_len, key, computed_tag);

    tweak[0] = TWEAK_TAG;
    memcpy(tweak + 1, nonce, 15);
    build_tweak_384(tweakey, key, tweak);
    deoxys_bc_384_encrypt(tweakey, computed_tag, computed_tag);

    if (memcmp(computed_tag, tag, 16) != 0) return -1;
    return (int)ct_len;
}