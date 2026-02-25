# AES-IGE-AEAD

Authenticated Encryption library: **AES-256-IGE** with polynomial MAC, **ChaCha20-Poly1305** (RFC 8439), and **Deoxys** (CAESAR finalist).

[![C99](https://img.shields.io/badge/C-C99-blue)](.)
[![No dependencies](https://img.shields.io/badge/dependencies-None-green)](.)

## Features

- **AEAD** — Authenticated Encryption with Associated Data
- **AES-256-IGE** — Full implementation from scratch (Infinite Garble Extension)
- **ChaCha20-Poly1305** — RFC 8439 (fast without AES-NI)
- **Deoxys** — CAESAR finalist: Deoxys-I-128, Deoxys-I-256, Deoxys-II-128, Deoxys-II-256
- **Polynomial MAC** — GF(2^128) GHASH-style (AES-IGE), Poly1305 (ChaCha20)
- **Zero dependencies** — Standard C only (C99)
- **Portable** — Windows, Linux, macOS

## Algorithms

| Algorithm | Key | IV/Nonce | Format |
|-----------|-----|----------|--------|
| AES-IGE-AEAD | 32 B | 32 B (IV) | IV \|\| CT \|\| Tag |
| ChaCha20-Poly1305 | 32 B | 12 B (nonce) | Nonce \|\| CT \|\| Tag |
| Deoxys-I-128 | 16 B | 8 B (nonce) | CT \|\| Tag |
| Deoxys-I-256 | 32 B | 8 B (nonce) | CT \|\| Tag |
| Deoxys-II-128 | 16 B | 15 B (nonce) | CT \|\| Tag |
| Deoxys-II-256 | 32 B | 15 B (nonce) | CT \|\| Tag |

## Build

### Windows (GCC/MinGW)

```bat
build.bat
```

Produces: `libaes_ige_aead.a`, `test_vectors.exe`, `demo.exe`

### Linux / macOS (Make)

```bash
make static
make test
make demo
```

### CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
ctest
```

## Usage

### AES-IGE-AEAD

```c
#include "aes_ige_aead.h"

uint8_t key[32], iv[32];
/* key: crypto random; iv: unique per encryption */

size_t ct_size = aes_ige_aead_encrypt_size(plaintext_len);
uint8_t *ciphertext = malloc(ct_size);

int ct_len = aes_ige_aead_encrypt(key, iv, aad, aad_len,
                                  plaintext, plaintext_len, ciphertext);

int pt_len = aes_ige_aead_decrypt(key, aad, aad_len,
                                  ciphertext, ct_len, plaintext_out);
```

### ChaCha20-Poly1305

```c
#include "chacha20_poly1305.h"

uint8_t key[32], nonce[12];
/* nonce: 12 bytes, unique per encryption */

int ct_len = chacha20_poly1305_encrypt(key, nonce, aad, aad_len,
                                       plaintext, pt_len, ciphertext);

int pt_len = chacha20_poly1305_decrypt(key, aad, aad_len,
                                       ciphertext, ct_len, plaintext);
```

### Deoxys (CAESAR finalist)

```c
#include "deoxys.h"

/* Deoxys-I-128: nonce 8 bytes, nonce-respecting */
uint8_t key_i128[16], nonce_i[8];
int ct_len = deoxys_i_128_encrypt(key_i128, nonce_i, aad, aad_len, pt, pt_len, ct);
int pt_len = deoxys_i_128_decrypt(key_i128, nonce_i, aad, aad_len, ct, ct_len, pt);

/* Deoxys-I-256: key 32 bytes */
int ct_len = deoxys_i_256_encrypt(key_i256, nonce_i, aad, aad_len, pt, pt_len, ct);

/* Deoxys-II-128: nonce 15 bytes, nonce-misuse resistant */
uint8_t nonce_ii[15];
int ct_len = deoxys_ii_128_encrypt(key_i128, nonce_ii, aad, aad_len, pt, pt_len, ct);

/* Deoxys-II-256 */
int ct_len = deoxys_ii_256_encrypt(key_i256, nonce_ii, aad, aad_len, pt, pt_len, ct);
```

## API Summary

| Function | Description |
|----------|-------------|
| `aes_ige_aead_encrypt_size(len)` | Ciphertext buffer size (AES-IGE) |
| `aes_ige_aead_decrypt_size(len)` | Max plaintext size |
| `aes_ige_aead_encrypt(...)` | Encrypt (AES-IGE) |
| `aes_ige_aead_decrypt(...)` | Decrypt and verify |
| `chacha20_poly1305_encrypt_size(len)` | Ciphertext size (ChaCha20) |
| `chacha20_poly1305_encrypt(...)` | Encrypt (ChaCha20-Poly1305) |
| `chacha20_poly1305_decrypt(...)` | Decrypt and verify |
| `deoxys_i_128_encrypt/decrypt` | Deoxys-I-128 |
| `deoxys_i_256_encrypt/decrypt` | Deoxys-I-256 |
| `deoxys_ii_128_encrypt/decrypt` | Deoxys-II-128 |
| `deoxys_ii_256_encrypt/decrypt` | Deoxys-II-256 |

## Documentation

| Document | Description |
|----------|-------------|
| [docs/SPEC.md](docs/SPEC.md) | AES-IGE-AEAD specification |
| [docs/CHACHA20_POLY1305.md](docs/CHACHA20_POLY1305.md) | ChaCha20-Poly1305 (RFC 8439) |
| [docs/API.md](docs/API.md) | API reference |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Integration guide |
| [docs/DEOXYS.md](docs/DEOXYS.md) | Deoxys (CAESAR) specification |

## Project Structure

```
AES-IGE_AEAD/
├── include/           # Headers
│   ├── aes_ige_aead.h
│   ├── chacha20_poly1305.h
│   ├── chacha20.h
│   ├── poly1305.h
│   └── deoxys.h
├── src/               # C sources
│   ├── sha256.c, aes.c, gf128.c
│   ├── aes_ige.c, poly_mac.c, aes_ige_aead.c
│   ├── chacha20.c, poly1305.c, chacha20_poly1305.c
│   ├── deoxys_bc.c, deoxys.c
├── tests/
│   └── test_vectors.c
├── demo/
│   └── demo.c
├── python/            # Python C extension
├── docs/
├── build.bat
├── Makefile
└── CMakeLists.txt
```

## Python binding

```bash
pip install ./python
```

```python
import os
from aes_ige_aead import encrypt, decrypt, KEY_SIZE, IV_SIZE

# AES-IGE-AEAD
key = os.urandom(KEY_SIZE)
iv = os.urandom(IV_SIZE)
ct = encrypt(key=key, iv=iv, plaintext=b"Secret")
pt = decrypt(key=key, ciphertext=ct)

# ChaCha20-Poly1305
from aes_ige_aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from aes_ige_aead import CHACHA20_POLY1305_NONCE_SIZE

nonce = os.urandom(CHACHA20_POLY1305_NONCE_SIZE)
ct = chacha20_poly1305_encrypt(key=key, nonce=nonce, plaintext=b"Secret")
pt = chacha20_poly1305_decrypt(key=key, ciphertext=ct)
```

See [python/README.md](python/README.md).

## License

Public Domain / MIT
