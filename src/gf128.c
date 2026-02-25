/**
 * GF(2^128) arithmetic
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1
 * Same as GCM (NIST SP 800-38D)
 * Byte order: big-endian, a[0] = MSB
 */
#include "gf128.h"
#include <string.h>

void gf128_zero(gf128_t r) {
    memset(r, 0, GF128_BLOCK_SIZE);
}

void gf128_from_bytes(gf128_t r, const uint8_t *b) {
    memcpy(r, b, GF128_BLOCK_SIZE);
}

void gf128_to_bytes(const gf128_t a, uint8_t *out) {
    memcpy(out, a, GF128_BLOCK_SIZE);
}

void gf128_add(gf128_t r, const gf128_t a, const gf128_t b) {
    size_t i;
    for (i = 0; i < 16; i++) {
        r[i] = a[i] ^ b[i];
    }
}

/* Multiplication: r = a * b in GF(2^128)
 * Algorithm: process bits of a from MSB to LSB, result = result*x + (bit?a)
 * Reduction: x^128 + x^7 + x^2 + x + 1 => XOR 0x87 when overflow
 */
void gf128_mul(gf128_t r, const gf128_t a, const gf128_t b) {
    gf128_t z;
    int i, j;
    uint8_t carry;

    gf128_zero(z);
    for (i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        unsigned int bit_a = (a[byte_idx] >> bit_idx) & 1;

        carry = z[0] >> 7;
        for (j = 0; j < 15; j++) {
            z[j] = (z[j] << 1) | (z[j + 1] >> 7);
        }
        z[15] = z[15] << 1;
        if (carry) z[15] ^= 0x87;

        if (bit_a) {
            for (j = 0; j < 16; j++) z[j] ^= b[j];
        }
    }
    memcpy(r, z, 16);
}
