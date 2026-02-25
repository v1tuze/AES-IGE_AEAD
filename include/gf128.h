/**
 * GF(2^128) arithmetic
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1 (GCM style)
 */
#ifndef GF128_H
#define GF128_H

#include <stdint.h>
#include <stddef.h>

#define GF128_BLOCK_SIZE 16

typedef uint8_t gf128_t[GF128_BLOCK_SIZE];

void gf128_zero(gf128_t r);
void gf128_from_bytes(gf128_t r, const uint8_t *b);
void gf128_to_bytes(const gf128_t a, uint8_t *out);
void gf128_add(gf128_t r, const gf128_t a, const gf128_t b);
void gf128_mul(gf128_t r, const gf128_t a, const gf128_t b);

#endif /* GF128_H */
