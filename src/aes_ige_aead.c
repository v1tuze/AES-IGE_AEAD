/**
 * AES-IGE AEAD implementation
 * KDF: HKDF-style with SHA-256 (extract: HMAC, expand: HKDF-expand)
 * Simplified: SHA256(key || 0x01) -> enc_key, SHA256(key || 0x02) -> mac_key
 */
#include "aes_ige_aead.h"
#include "aes_ige.h"
#include "poly_mac.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

static void hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t digest[32]) {
    sha256_ctx_t ctx;
    uint8_t ipad[64], opad[64];
    uint8_t hkey[32];
    size_t i;

    if (key_len > 64) {
        sha256(key, key_len, hkey);
        key = hkey;
        key_len = 32;
    }

    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (i = 0; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, digest);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, digest, 32);
    sha256_final(&ctx, digest);
}

/* KDF: derive enc_key (32) and mac_key (16) from master key */
static void kdf(const uint8_t key[32], uint8_t enc_key[32], uint8_t mac_key[16]) {
    uint8_t t[32];
    uint8_t info1 = 0x01, info2 = 0x02;

    hmac_sha256(key, 32, &info1, 1, t);
    memcpy(enc_key, t, 32);

    hmac_sha256(key, 32, &info2, 1, t);
    memcpy(mac_key, t, 16);
}

int aes_ige_aead_encrypt(const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
                         const uint8_t iv[AES_IGE_AEAD_IV_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t pt_len,
                         uint8_t *ciphertext) {
    uint8_t enc_key[32], mac_key[16];
    int ct_len;
    size_t total_ct;

    if (!key || !iv || !ciphertext) return -1;
    if (pt_len > 0 && !plaintext) return -1;

    kdf(key, enc_key, mac_key);
    memcpy(ciphertext, iv, 32);
    ct_len = aes_ige_encrypt(enc_key, 32, iv, plaintext, pt_len, ciphertext + 32);
    if (ct_len < 0) return -1;

    total_ct = (size_t)ct_len;
    poly_mac(mac_key, 16, aad, aad_len, iv, 32,
             ciphertext + 32, total_ct, ciphertext + 32 + total_ct);
    return (int)(32 + total_ct + 16);
}

int aes_ige_aead_decrypt(const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t *plaintext) {
    uint8_t enc_key[32], mac_key[16];
    const uint8_t *iv, *ct, *tag;
    size_t actual_ct_len;
    int pt_len;

    if (ct_len < 32 + 16) return -1;
    if (!key || !ciphertext || !plaintext) return -1;

    iv = ciphertext;
    ct = ciphertext + 32;
    actual_ct_len = ct_len - 32 - 16;
    tag = ciphertext + 32 + actual_ct_len;

    kdf(key, enc_key, mac_key);
    if (poly_mac_verify(mac_key, 16, aad, aad_len, iv, 32, ct, actual_ct_len, tag) != 0)
        return -1;

    pt_len = aes_ige_decrypt(enc_key, 32, iv, ct, actual_ct_len, plaintext);
    return pt_len;
}
