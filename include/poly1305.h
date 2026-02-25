/**
 * Poly1305 one-time authenticator - RFC 8439
 * Key: 32 bytes (r || s)
 */
#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16

void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len,
                  uint8_t tag[16]);

#endif /* POLY1305_H */
