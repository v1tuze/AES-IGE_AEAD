/**
 * AES-256 implementation
 * FIPS-197 compliant
 */
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define AES_KEY_SCHEDULE_WORDS 60

typedef struct {
    uint32_t round_keys[AES_KEY_SCHEDULE_WORDS];
} aes_ctx_t;

void aes_init(aes_ctx_t *ctx, const uint8_t key[AES_KEY_SIZE]);
void aes_encrypt_block(const aes_ctx_t *ctx, const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt_block(const aes_ctx_t *ctx, const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE]);

#endif /* AES_H */
