/**
 * Deoxys-BC - AES-based tweakable block cipher (internal)
 * Deoxys-BC-256: 256-bit tweakey, 14 rounds
 * Deoxys-BC-384: 384-bit tweakey, 16 rounds
 */
#ifndef DEOXYS_BC_H
#define DEOXYS_BC_H

#include <stdint.h>

#define DEOXYS_BC_BLOCK_SIZE 16
#define DEOXYS_BC_256_TWEAKEY 32  /* key 16 + tweak 16 */
#define DEOXYS_BC_384_TWEAKEY 48  /* key 32 + tweak 16 */
#define DEOXYS_BC_256_ROUNDS  14
#define DEOXYS_BC_384_ROUNDS  16

/* Encrypt one block */
void deoxys_bc_256_encrypt(const uint8_t tweakey[32], const uint8_t plaintext[16],
                           uint8_t ciphertext[16]);
void deoxys_bc_384_encrypt(const uint8_t tweakey[48], const uint8_t plaintext[16],
                           uint8_t ciphertext[16]);

/* Decrypt one block */
void deoxys_bc_256_decrypt(const uint8_t tweakey[32], const uint8_t ciphertext[16],
                           uint8_t plaintext[16]);
void deoxys_bc_384_decrypt(const uint8_t tweakey[48], const uint8_t ciphertext[16],
                           uint8_t plaintext[16]);

#endif /* DEOXYS_BC_H */
