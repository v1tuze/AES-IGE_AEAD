/**
 * Poly1305 - RFC 8439, 5x26-bit limb representation
 */
#include "poly1305.h"
#include <string.h>

#define U8TO32(p) ((uint32_t)(p)[0]|(uint32_t)(p)[1]<<8|(uint32_t)(p)[2]<<16|(uint32_t)(p)[3]<<24)
#define U32TO8(p,v) do{(p)[0]=(uint8_t)(v);(p)[1]=(uint8_t)((v)>>8);(p)[2]=(uint8_t)((v)>>16);(p)[3]=(uint8_t)((v)>>24);}while(0)

void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len,
                  uint8_t tag[16]) {
    uint8_t k[32];
    uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4;
    uint64_t f;
    memcpy(k, key, 32);
    k[3] &= 15; k[7] &= 15; k[11] &= 15; k[15] &= 15;
    k[4] &= 252; k[8] &= 252; k[12] &= 252;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c, hibit;
    size_t nblocks = len / 16;
    size_t i;

    r0 = (U8TO32(&k[0])     ) & 0x3ffffff;
    r1 = (U8TO32(&k[3]) >> 2) & 0x3ffffff;
    r2 = (U8TO32(&k[6]) >> 4) & 0x3ffffff;
    r3 = (U8TO32(&k[9]) >> 6) & 0x3ffffff;
    r4 = (U8TO32(&k[12])>> 8) & 0x3ffffff;
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

    h0 = h1 = h2 = h3 = h4 = 0;

    for (i = 0; i < nblocks; i++) {
        hibit = (uint32_t)(1 << 24);
        h0 += (U8TO32(msg + 0)     ) & 0x3ffffff;
        h1 += (U8TO32(msg + 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32(msg + 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32(msg + 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32(msg + 12)>> 8) | hibit;

        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        msg += 16;
    }

    if (len % 16) {
        uint8_t block[16];
        size_t rem = len % 16;
        memset(block, 0, 16);
        memcpy(block, msg, rem);
        block[rem] = 1;

        hibit = 0;
        h0 += (U8TO32(block + 0)     ) & 0x3ffffff;
        h1 += (U8TO32(block + 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32(block + 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32(block + 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32(block + 12)>> 8) | hibit;

        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    {
        uint32_t g0, g1, g2, g3, g4;
        uint32_t mask;
        g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff; g1 = h1 + c;
        c = g1 >> 26; g1 &= 0x3ffffff; g2 = h2 + c;
        c = g2 >> 26; g2 &= 0x3ffffff; g3 = h3 + c;
        c = g3 >> 26; g3 &= 0x3ffffff; g4 = h4 + c - (1U << 26);
        mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    }

    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    f = (uint64_t)h0 + U8TO32(&k[16]); h0 = (uint32_t)f;
    f = (uint64_t)h1 + U8TO32(&k[20]) + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + U8TO32(&k[24]) + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + U8TO32(&k[28]) + (f >> 32); h3 = (uint32_t)f;

    U32TO8(tag + 0, h0); U32TO8(tag + 4, h1);
    U32TO8(tag + 8, h2); U32TO8(tag + 12, h3);
}
