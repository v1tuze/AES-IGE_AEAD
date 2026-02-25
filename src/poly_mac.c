/**
 * Polynomial MAC in GF(2^128)
 * Input: AAD || len_aad(8) || IV || len_iv(8) || CT || len_ct(8)
 * Padded to 16-byte blocks, then GHASH-style evaluation
 */
#include "poly_mac.h"
#include "gf128.h"
#include <string.h>
#include <stdlib.h>

/* Encode lengths as 8-byte big-endian */
static void encode_len(uint8_t *out, size_t len) {
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(len & 0xff);
        len >>= 8;
    }
}

static void poly_mac_blocks(const gf128_t key,
                            const uint8_t *data, size_t num_blocks,
                            gf128_t result) {
    size_t i;
    gf128_t tmp;

    gf128_zero(result);
    for (i = 0; i < num_blocks; i++) {
        gf128_add(tmp, result, (const uint8_t *)&data[i * 16]);
        gf128_mul(result, tmp, key);
    }
}

void poly_mac(const uint8_t *key, size_t key_len,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *iv, size_t iv_len,
              const uint8_t *ciphertext, size_t ct_len,
              uint8_t tag[POLY_MAC_TAG_SIZE]) {
    gf128_t K, H;
    uint8_t len_buf[16];
    size_t aad_pad, iv_pad, ct_pad, total_len, num_blocks;
    uint8_t *buf = NULL;
    size_t off = 0;

    if (key_len < 16) return;
    gf128_from_bytes(K, key);

    aad_pad = aad_len % 16 ? 16 - (aad_len % 16) : 0;
    iv_pad = iv_len % 16 ? 16 - (iv_len % 16) : 0;
    ct_pad = ct_len % 16 ? 16 - (ct_len % 16) : 0;
    total_len = aad_len + aad_pad + iv_len + iv_pad + ct_len + ct_pad + 16;
    num_blocks = total_len / 16;
    buf = (uint8_t *)malloc(total_len);
    if (!buf) return;

    if (aad_len > 0 && aad) {
        memcpy(buf, aad, aad_len);
        off = aad_len;
        if (aad_pad) memset(buf + off, 0, aad_pad), off += aad_pad;
    }

    if (iv_len > 0 && iv) {
        memcpy(buf + off, iv, iv_len);
        off += iv_len;
        if (iv_pad) memset(buf + off, 0, iv_pad), off += iv_pad;
    }

    if (ct_len > 0 && ciphertext) {
        memcpy(buf + off, ciphertext, ct_len);
        off += ct_len;
        if (ct_pad) memset(buf + off, 0, ct_pad), off += ct_pad;
    }

    encode_len(len_buf, aad_len);
    encode_len(len_buf + 8, ct_len);
    memcpy(buf + off, len_buf, 16);

    poly_mac_blocks(K, buf, num_blocks, H);
    gf128_to_bytes(H, tag);
    free(buf);
}

int poly_mac_verify(const uint8_t *key, size_t key_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t tag[POLY_MAC_TAG_SIZE]) {
    uint8_t computed[POLY_MAC_TAG_SIZE];
    poly_mac(key, key_len, aad, aad_len, iv, iv_len, ciphertext, ct_len, computed);
    return (memcmp(computed, tag, POLY_MAC_TAG_SIZE) == 0) ? 0 : -1;
}
