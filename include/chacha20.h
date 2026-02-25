/**
 * ChaCha20 stream cipher - RFC 8439
 */
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64

void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t out[64]);

void chacha20_xor(const uint8_t key[32], uint32_t counter,
                  const uint8_t nonce[12],
                  const uint8_t *in, uint8_t *out, size_t len);

#endif /* CHACHA20_H */
