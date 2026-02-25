/**
 * ChaCha20-Poly1305 AEAD - RFC 8439
 * Output format: Nonce (12) || Ciphertext || Tag (16)
 */
#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_POLY1305_KEY_SIZE   32
#define CHACHA20_POLY1305_NONCE_SIZE 12
#define CHACHA20_POLY1305_TAG_SIZE   16
#define CHACHA20_POLY1305_OVERHEAD   (CHACHA20_POLY1305_NONCE_SIZE + CHACHA20_POLY1305_TAG_SIZE)

static inline size_t chacha20_poly1305_encrypt_size(size_t plaintext_len) {
    return CHACHA20_POLY1305_OVERHEAD + plaintext_len;
}

static inline size_t chacha20_poly1305_decrypt_size(size_t ct_len) {
    if (ct_len < CHACHA20_POLY1305_OVERHEAD) return 0;
    return ct_len - CHACHA20_POLY1305_OVERHEAD;
}

int chacha20_poly1305_encrypt(const uint8_t key[CHACHA20_POLY1305_KEY_SIZE],
                              const uint8_t nonce[CHACHA20_POLY1305_NONCE_SIZE],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext);

int chacha20_poly1305_decrypt(const uint8_t key[CHACHA20_POLY1305_KEY_SIZE],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext);

#endif /* CHACHA20_POLY1305_H */
