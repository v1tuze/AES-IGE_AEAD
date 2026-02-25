# AES-IGE-AEAD API Reference

## Header

```c
#include "aes_ige_aead.h"
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `AES_IGE_AEAD_KEY_SIZE` | 32 | Master key size (bytes) |
| `AES_IGE_AEAD_IV_SIZE` | 32 | IV size (bytes) |
| `AES_IGE_AEAD_TAG_SIZE` | 16 | Tag size (bytes) |
| `AES_IGE_AEAD_OVERHEAD` | 48 | IV + Tag overhead |

## Buffer Size Functions

### aes_ige_aead_encrypt_size

```c
size_t aes_ige_aead_encrypt_size(size_t plaintext_len);
```

Returns the required ciphertext buffer size for encrypting `plaintext_len` bytes.

### aes_ige_aead_decrypt_size

```c
size_t aes_ige_aead_decrypt_size(size_t ct_len);
```

Returns the maximum plaintext size when decrypting `ct_len` bytes. Returns 0 if `ct_len < OVERHEAD`.

## Core Functions

### aes_ige_aead_encrypt

```c
int aes_ige_aead_encrypt(
    const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
    const uint8_t iv[AES_IGE_AEAD_IV_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext);
```

**Parameters:**
- `key` — Master key
- `iv` — Initialization vector (must be random and unique)
- `aad` — Associated data (NULL if aad_len=0)
- `aad_len` — Length of AAD
- `plaintext` — Data to encrypt (NULL if plaintext_len=0)
- `plaintext_len` — Length of plaintext
- `ciphertext` — Output buffer

**Returns:** Ciphertext length on success, -1 on error.

### aes_ige_aead_decrypt

```c
int aes_ige_aead_decrypt(
    const uint8_t key[AES_IGE_AEAD_KEY_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext);
```

**Parameters:**
- `key` — Master key
- `aad` — Associated data (same as encrypt)
- `aad_len` — Length of AAD
- `ciphertext` — Full ciphertext (IV||CT||Tag)
- `ciphertext_len` — Total length
- `plaintext` — Output buffer

**Returns:** Plaintext length on success, -1 on auth failure or error.
