/**
 * AES-IGE-AEAD - Authenticated Encryption Library
 *
 * Full specification: AES-256-IGE + Polynomial MAC (GF(2^128))
 * Ciphertext format: IV (32 bytes) || Ciphertext || Tag (16 bytes)
 *
 * Version: 1.0.0
 * License: Public Domain / MIT
 *
 * @file aes_ige_aead.h
 */

#ifndef AES_IGE_AEAD_H
#define AES_IGE_AEAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */

#define AES_IGE_AEAD_VERSION_MAJOR 1
#define AES_IGE_AEAD_VERSION_MINOR 0
#define AES_IGE_AEAD_VERSION_PATCH 0

#define AES_IGE_AEAD_KEY_SIZE  32   /**< Master key size (bytes) */
#define AES_IGE_AEAD_IV_SIZE   32   /**< IV size (bytes) - must be unique per encryption */
#define AES_IGE_AEAD_TAG_SIZE  16   /**< Authentication tag size (bytes) */

/* Overhead: IV + Tag (ciphertext = plaintext + padding + overhead) */
#define AES_IGE_AEAD_OVERHEAD  (AES_IGE_AEAD_IV_SIZE + AES_IGE_AEAD_TAG_SIZE)

/* ---------------------------------------------------------------------------
 * Buffer size helpers
 * --------------------------------------------------------------------------- */

/**
 * Maximum ciphertext length for given plaintext length.
 * Use this to allocate ciphertext buffer before encryption.
 * Formula: 32 (IV) + ceil(plaintext_len/16)*16 (padded CT) + 16 (Tag)
 */
static inline size_t aes_ige_aead_encrypt_size(size_t plaintext_len) {
    size_t padded = plaintext_len + (16 - (plaintext_len % 16));
    if (plaintext_len == 0) padded = 16;
    return AES_IGE_AEAD_OVERHEAD + padded;
}

/**
 * Maximum plaintext length for given ciphertext length.
 * Use this to allocate plaintext buffer before decryption.
 * Returns 0 if ct_len is too short.
 */
static inline size_t aes_ige_aead_decrypt_size(size_t ct_len) {
    if (ct_len < AES_IGE_AEAD_OVERHEAD) return 0;
    return ct_len - AES_IGE_AEAD_OVERHEAD;  /* Max before padding removal */
}

/* ---------------------------------------------------------------------------
 * Core API
 * --------------------------------------------------------------------------- */

/**
 * Encrypt plaintext with authenticated encryption.
 *
 * @param key         Master key (AES_IGE_AEAD_KEY_SIZE bytes)
 * @param iv          Initialization vector (AES_IGE_AEAD_IV_SIZE bytes).
 *                    MUST be cryptographically random and unique per encryption.
 * @param aad         Associated authenticated data (may be NULL if aad_len=0)
 * @param aad_len     Length of AAD in bytes
 * @param plaintext   Data to encrypt (may be NULL if plaintext_len=0)
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext  Output buffer (use aes_ige_aead_encrypt_size() for sizing)
 * @return            Ciphertext length (IV||CT||Tag) on success, -1 on error
 */
int aes_ige_aead_encrypt(const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
                         const uint8_t iv[AES_IGE_AEAD_IV_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext);

/**
 * Decrypt and verify ciphertext.
 *
 * @param key         Master key (same as encrypt)
 * @param aad         Associated data (same as encrypt; NULL if aad_len=0)
 * @param aad_len     Length of AAD
 * @param ciphertext  Full ciphertext (IV||CT||Tag)
 * @param ciphertext_len Total length
 * @param plaintext   Output buffer (use aes_ige_aead_decrypt_size() for max size)
 * @return            Plaintext length on success, -1 on auth failure or error
 */
int aes_ige_aead_decrypt(const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* AES_IGE_AEAD_H */
