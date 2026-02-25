/**
 * AES-IGE (Infinite Garble Extension) mode
 * OpenSSL convention: IV = 32 bytes (x0 || y0)
 * Encryption: y_i = E_K(x_i XOR y_{i-1}) XOR x_{i-1}
 * Decryption: x_i = D_K(y_i XOR x_{i-1}) XOR y_{i-1}
 */
#ifndef AES_IGE_H
#define AES_IGE_H

#include <stddef.h>
#include <stdint.h>
#include "aes.h"

#define AES_IGE_IV_SIZE 32
#define AES_IGE_BLOCK_SIZE 16

int aes_ige_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext);
int aes_ige_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *ciphertext, size_t ct_len,
                    uint8_t *plaintext);

/* Raw block API (caller handles padding, length must be multiple of 16) */
void aes_ige_encrypt_blocks(aes_ctx_t *ctx, const uint8_t *iv,
                             const uint8_t *in, uint8_t *out, size_t num_blocks);
void aes_ige_decrypt_blocks(aes_ctx_t *ctx, const uint8_t *iv,
                             const uint8_t *in, uint8_t *out, size_t num_blocks);

#endif /* AES_IGE_H */
