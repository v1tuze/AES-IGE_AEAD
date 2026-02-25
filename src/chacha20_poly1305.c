/**
 * ChaCha20-Poly1305 AEAD - RFC 8439
 */
#include "chacha20_poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include <stdlib.h>
#include <string.h>

static void le64(uint8_t *out, uint64_t v) {
    out[0] = (uint8_t)(v); out[1] = (uint8_t)(v>>8);
    out[2] = (uint8_t)(v>>16); out[3] = (uint8_t)(v>>24);
    out[4] = (uint8_t)(v>>32); out[5] = (uint8_t)(v>>40);
    out[6] = (uint8_t)(v>>48); out[7] = (uint8_t)(v>>56);
}

int chacha20_poly1305_encrypt(const uint8_t key[CHACHA20_POLY1305_KEY_SIZE],
                              const uint8_t nonce[CHACHA20_POLY1305_NONCE_SIZE],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext) {
    uint8_t block[64];
    uint8_t *mac_buf = NULL;
    size_t aad_pad, ct_pad, mac_len;
    size_t off = 0;

    if (!key || !nonce || !ciphertext) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    memcpy(ciphertext, nonce, 12);
    chacha20_block(key, 0, nonce, block);
    chacha20_xor(key, 1, nonce, plaintext, ciphertext + 12, plaintext_len);

    aad_pad = (16 - (aad_len % 16)) % 16;
    ct_pad = (16 - (plaintext_len % 16)) % 16;
    mac_len = aad_len + aad_pad + plaintext_len + ct_pad + 16;

    mac_buf = (uint8_t *)malloc(mac_len);
    if (!mac_buf) return -1;

    if (aad_len > 0 && aad) { memcpy(mac_buf, aad, aad_len); off = aad_len; }
    if (aad_pad) memset(mac_buf + off, 0, aad_pad), off += aad_pad;
    memcpy(mac_buf + off, ciphertext + 12, plaintext_len); off += plaintext_len;
    if (ct_pad) memset(mac_buf + off, 0, ct_pad), off += ct_pad;
    le64(mac_buf + off, aad_len); le64(mac_buf + off + 8, plaintext_len);

    poly1305_mac(block, mac_buf, mac_len, ciphertext + 12 + plaintext_len);
    free(mac_buf);
    return (int)(12 + plaintext_len + 16);
}

int chacha20_poly1305_decrypt(const uint8_t key[CHACHA20_POLY1305_KEY_SIZE],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext) {
    const uint8_t *nonce, *ct, *tag;
    uint8_t block[64], computed_tag[16];
    uint8_t *mac_buf = NULL;
    size_t pt_len, aad_pad, ct_pad, mac_len;
    size_t off = 0;

    if (ciphertext_len < 12 + 16) return -1;
    if (!key || !ciphertext || !plaintext) return -1;

    nonce = ciphertext;
    pt_len = ciphertext_len - 12 - 16;
    ct = ciphertext + 12;
    tag = ciphertext + 12 + pt_len;

    chacha20_block(key, 0, nonce, block);

    aad_pad = (16 - (aad_len % 16)) % 16;
    ct_pad = (16 - (pt_len % 16)) % 16;
    mac_len = aad_len + aad_pad + pt_len + ct_pad + 16;

    mac_buf = (uint8_t *)malloc(mac_len);
    if (!mac_buf) return -1;

    if (aad_len > 0 && aad) { memcpy(mac_buf, aad, aad_len); off = aad_len; }
    if (aad_pad) memset(mac_buf + off, 0, aad_pad), off += aad_pad;
    memcpy(mac_buf + off, ct, pt_len); off += pt_len;
    if (ct_pad) memset(mac_buf + off, 0, ct_pad), off += ct_pad;
    le64(mac_buf + off, aad_len); le64(mac_buf + off + 8, pt_len);

    poly1305_mac(block, mac_buf, mac_len, computed_tag);
    free(mac_buf);

    if (memcmp(computed_tag, tag, 16) != 0) return -1;

    chacha20_xor(key, 1, nonce, ct, plaintext, pt_len);
    return (int)pt_len;
}

