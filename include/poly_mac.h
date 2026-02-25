/**
 * Polynomial MAC in GF(2^128)
 * GHASH-style: H = ((((B1*K + B2)*K + ...)*K + Bn) for blocks B1..Bn
 * Authenticates: AAD || IV || Ciphertext (with length encoding)
 */
#ifndef POLY_MAC_H
#define POLY_MAC_H

#include <stddef.h>
#include <stdint.h>

#define POLY_MAC_TAG_SIZE 16

void poly_mac(const uint8_t *key, size_t key_len,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *iv, size_t iv_len,
              const uint8_t *ciphertext, size_t ct_len,
              uint8_t tag[POLY_MAC_TAG_SIZE]);

int poly_mac_verify(const uint8_t *key, size_t key_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t tag[POLY_MAC_TAG_SIZE]);

#endif /* POLY_MAC_H */
