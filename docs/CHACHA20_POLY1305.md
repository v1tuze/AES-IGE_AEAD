# ChaCha20-Poly1305

RFC 8439 implementation. Output format: `Nonce (12) || Ciphertext || Tag (16)`.

## Parameters

| Parameter | Value |
|-----------|-------|
| Key | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes) |
| Tag | 128 bits (16 bytes) |

## API (C)

```c
#include "chacha20_poly1305.h"

int chacha20_poly1305_encrypt(const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext);

int chacha20_poly1305_decrypt(const uint8_t key[32],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *plaintext);

size_t chacha20_poly1305_encrypt_size(size_t plaintext_len);
size_t chacha20_poly1305_decrypt_size(size_t ciphertext_len);
```

## Python

```python
from aes_ige_aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from aes_ige_aead import KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE

key = os.urandom(KEY_SIZE)
nonce = os.urandom(CHACHA20_POLY1305_NONCE_SIZE)
ct = chacha20_poly1305_encrypt(key=key, nonce=nonce, plaintext=b"Secret")
pt = chacha20_poly1305_decrypt(key=key, ciphertext=ct)
```
