/**
 * AES-IGE mode implementation
 * IV format: x0 (16 bytes) || y0 (16 bytes)
 */
#include "aes_ige.h"
#include <string.h>
#include <stdlib.h>

static void xor_block(uint8_t *r, const uint8_t *a, const uint8_t *b) {
    int i;
    for (i = 0; i < 16; i++) r[i] = a[i] ^ b[i];
}

void aes_ige_encrypt_blocks(aes_ctx_t *ctx, const uint8_t *iv,
                            const uint8_t *in, uint8_t *out, size_t num_blocks) {
    const uint8_t *x0 = iv;
    const uint8_t *y0 = iv + 16;
    uint8_t x_prev[16], y_prev[16];
    uint8_t tmp[16];
    size_t i;

    memcpy(x_prev, x0, 16);
    memcpy(y_prev, y0, 16);

    for (i = 0; i < num_blocks; i++) {
        xor_block(tmp, &in[i * 16], y_prev);
        aes_encrypt_block(ctx, tmp, &out[i * 16]);
        xor_block(&out[i * 16], &out[i * 16], x_prev);
        memcpy(x_prev, &in[i * 16], 16);
        memcpy(y_prev, &out[i * 16], 16);
    }
}

void aes_ige_decrypt_blocks(aes_ctx_t *ctx, const uint8_t *iv,
                            const uint8_t *in, uint8_t *out, size_t num_blocks) {
    const uint8_t *x0 = iv;
    const uint8_t *y0 = iv + 16;
    uint8_t x_prev[16], y_prev[16];
    uint8_t tmp[16];
    size_t i;

    memcpy(x_prev, x0, 16);
    memcpy(y_prev, y0, 16);

    for (i = 0; i < num_blocks; i++) {
        xor_block(tmp, &in[i * 16], x_prev);
        aes_decrypt_block(ctx, tmp, &out[i * 16]);
        xor_block(&out[i * 16], &out[i * 16], y_prev);
        memcpy(x_prev, &out[i * 16], 16);
        memcpy(y_prev, &in[i * 16], 16);
    }
}

static size_t pkcs7_pad(uint8_t *buf, size_t len, size_t block_size) {
    size_t pad_len = block_size - (len % block_size);
    size_t i;
    for (i = 0; i < pad_len; i++) buf[len + i] = (uint8_t)pad_len;
    return len + pad_len;
}

static int pkcs7_unpad(const uint8_t *buf, size_t len, size_t *out_len) {
    uint8_t pad_val;
    size_t i;
    if (len == 0 || len % 16 != 0) return -1;
    pad_val = buf[len - 1];
    if (pad_val == 0 || pad_val > 16) return -1;
    for (i = 1; i < pad_val; i++) {
        if (buf[len - 1 - i] != pad_val) return -1;
    }
    *out_len = len - pad_val;
    return 0;
}

int aes_ige_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext) {
    aes_ctx_t ctx;
    uint8_t *padded = NULL;
    size_t padded_len;
    int ret = -1;

    if (key_len != 32) return -1;
    if (!iv || !ciphertext) return -1;
    if (pt_len > 0 && !plaintext) return -1;

    padded_len = pt_len ? pt_len + (16 - (pt_len % 16)) : 16;
    padded = (uint8_t *)malloc(padded_len);
    if (!padded) return -1;

    if (pt_len > 0) memcpy(padded, plaintext, pt_len);
    pkcs7_pad(padded, pt_len, 16);

    aes_init(&ctx, key);
    aes_ige_encrypt_blocks(&ctx, iv, padded, ciphertext, padded_len / 16);
    ret = (int)padded_len;

    free(padded);
    return ret;
}

int aes_ige_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *ciphertext, size_t ct_len,
                    uint8_t *plaintext) {
    aes_ctx_t ctx;
    uint8_t *padded = NULL;
    size_t out_len;
    int ret = -1;

    if (key_len != 32) return -1;
    if (ct_len % 16 != 0) return -1;
    if (!iv || !ciphertext || !plaintext) return -1;

    padded = (uint8_t *)malloc(ct_len);
    if (!padded) return -1;

    aes_init(&ctx, key);
    aes_ige_decrypt_blocks(&ctx, iv, ciphertext, padded, ct_len / 16);

    if (pkcs7_unpad(padded, ct_len, &out_len) == 0) {
        memcpy(plaintext, padded, out_len);
        ret = (int)out_len;
    }

    free(padded);
    return ret;
}
