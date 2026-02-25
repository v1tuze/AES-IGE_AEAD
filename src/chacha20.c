/**
 * ChaCha20 - RFC 8439
 */
#include "chacha20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = ROTL32(d, 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL32(b, 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL32(d, 8); \
    (c) += (d); (b) ^= (c); (b) = ROTL32(b, 7); \
} while (0)

static void chacha20_core(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    int i;

    memcpy(x, in, 64);
    for (i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t state[16], result[16];
    int i;

    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    for (i = 0; i < 8; i++) {
        state[4 + i] = (uint32_t)key[i*4] | (key[i*4+1]<<8) |
                       (key[i*4+2]<<16) | (key[i*4+3]<<24);
    }
    state[12] = counter;
    state[13] = (uint32_t)nonce[0] | (nonce[1]<<8) | (nonce[2]<<16) | (nonce[3]<<24);
    state[14] = (uint32_t)nonce[4] | (nonce[5]<<8) | (nonce[6]<<16) | (nonce[7]<<24);
    state[15] = (uint32_t)nonce[8] | (nonce[9]<<8) | (nonce[10]<<16) | (nonce[11]<<24);

    chacha20_core(result, state);
    for (i = 0; i < 16; i++) {
        out[i*4]     = (uint8_t)(result[i]);
        out[i*4 + 1] = (uint8_t)(result[i] >> 8);
        out[i*4 + 2] = (uint8_t)(result[i] >> 16);
        out[i*4 + 3] = (uint8_t)(result[i] >> 24);
    }
}

void chacha20_xor(const uint8_t key[32], uint32_t counter,
                  const uint8_t nonce[12],
                  const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t i, n;

    while (len) {
        chacha20_block(key, counter, nonce, block);
        n = len < 64 ? len : 64;
        for (i = 0; i < n; i++) out[i] = in[i] ^ block[i];
        in += n; out += n; len -= n; counter++;
    }
}
