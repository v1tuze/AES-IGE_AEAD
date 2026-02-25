/**
 * Deoxys AEAD - CAESAR finalist
 * Deoxys-I (nonce-respecting), Deoxys-II (nonce-misuse resistant)
 * Format: Ciphertext || Tag (16 bytes)
 */
#ifndef DEOXYS_H
#define DEOXYS_H

#include <stddef.h>
#include <stdint.h>

/* Deoxys-I-128-128: 128-bit key, 8-byte nonce */
#define DEOXYS_I_128_KEY_SIZE   16
#define DEOXYS_I_128_NONCE_SIZE  8
#define DEOXYS_I_128_TAG_SIZE   16

/* Deoxys-I-256-128: 256-bit key, 8-byte nonce */
#define DEOXYS_I_256_KEY_SIZE   32
#define DEOXYS_I_256_NONCE_SIZE  8
#define DEOXYS_I_256_TAG_SIZE   16

/* Deoxys-II-128-128: 128-bit key, 15-byte nonce */
#define DEOXYS_II_128_KEY_SIZE   16
#define DEOXYS_II_128_NONCE_SIZE 15
#define DEOXYS_II_128_TAG_SIZE   16

/* Deoxys-II-256-128: 256-bit key, 15-byte nonce */
#define DEOXYS_II_256_KEY_SIZE   32
#define DEOXYS_II_256_NONCE_SIZE 15
#define DEOXYS_II_256_TAG_SIZE   16

#define DEOXYS_TAG_SIZE 16

/* Buffer size helpers - Deoxys-I */
static inline size_t deoxys_i_128_encrypt_size(size_t pt_len) {
    return ((pt_len + 15) / 16) * 16 + DEOXYS_TAG_SIZE;  /* padded to 16 + tag */
}
static inline size_t deoxys_i_256_encrypt_size(size_t pt_len) {
    return deoxys_i_128_encrypt_size(pt_len);
}

/* Buffer size helpers - Deoxys-II (no padding, plaintext length preserved) */
static inline size_t deoxys_ii_128_encrypt_size(size_t pt_len) {
    return pt_len + DEOXYS_TAG_SIZE;
}
static inline size_t deoxys_ii_256_encrypt_size(size_t pt_len) {
    return pt_len + DEOXYS_TAG_SIZE;
}

/* Deoxys-I-128: nonce 8 bytes, key 16 bytes */
int deoxys_i_128_encrypt(const uint8_t key[DEOXYS_I_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext);

int deoxys_i_128_decrypt(const uint8_t key[DEOXYS_I_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext);

/* Deoxys-I-256 */
int deoxys_i_256_encrypt(const uint8_t key[DEOXYS_I_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext);

int deoxys_i_256_decrypt(const uint8_t key[DEOXYS_I_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_I_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext);

/* Deoxys-II-128: nonce 15 bytes, key 16 bytes, nonce-misuse resistant */
int deoxys_ii_128_encrypt(const uint8_t key[DEOXYS_II_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_II_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext);

int deoxys_ii_128_decrypt(const uint8_t key[DEOXYS_II_128_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_II_128_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext);

/* Deoxys-II-256 */
int deoxys_ii_256_encrypt(const uint8_t key[DEOXYS_II_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_II_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext);

int deoxys_ii_256_decrypt(const uint8_t key[DEOXYS_II_256_KEY_SIZE],
                         const uint8_t nonce[DEOXYS_II_256_NONCE_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext);

#endif /* DEOXYS_H */
