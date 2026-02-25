# Integration Guide

## Quick Start

1. Copy `include/aes_ige_aead.h` to your project.
2. Compile and link the library sources (or use the static library).
3. Include the header and call the API.

## Building the Library

### Windows (GCC/MinGW)

```bat
build.bat
```

Produces: `libaes_ige_aead.a`, `test_vectors.exe`, `demo.exe`

### Unix / Make

```bash
make static
```

Produces: `libaes_ige_aead.a`

### CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Linking

### Static Library

```bash
gcc -o myapp myapp.c -I/path/to/include -L/path/to/lib -laes_ige_aead
```

### Object Files

```bash
gcc -o myapp myapp.c sha256.o aes.o gf128.o aes_ige.o poly_mac.o aes_ige_aead.o -Iinclude
```

## Minimal Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_ige_aead.h"

int main(void) {
    uint8_t key[32];
    uint8_t iv[32];
    const char *msg = "Hello, World!";
    size_t pt_len = strlen(msg);
    size_t ct_size = aes_ige_aead_encrypt_size(pt_len);
    uint8_t *ct = malloc(ct_size);
    uint8_t *pt = malloc(aes_ige_aead_decrypt_size(ct_size));
    int ct_len, pt_len_out;

    /* In production: use crypto-secure random for key and iv */
    memset(key, 0x42, 32);
    memset(iv, 0x77, 32);

    ct_len = aes_ige_aead_encrypt(key, iv, NULL, 0,
                                  (const uint8_t *)msg, pt_len, ct);
    if (ct_len < 0) { fprintf(stderr, "Encrypt failed\n"); return 1; }

    pt_len_out = aes_ige_aead_decrypt(key, NULL, 0, ct, ct_len, pt);
    if (pt_len_out < 0) { fprintf(stderr, "Decrypt/auth failed\n"); return 1; }

    printf("%.*s\n", pt_len_out, pt);
    free(ct); free(pt);
    return 0;
}
```

## IV Generation

**Critical:** IV must be unique for each encryption with the same key. Use a cryptographically secure random number generator:

- Windows: `BCryptGenRandom` or `CryptGenRandom`
- Unix: `/dev/urandom` or `getrandom()`
- Cross-platform: OpenSSL `RAND_bytes()`, libsodium `randombytes()`, etc.

```c
/* Example: fill IV from /dev/urandom (Unix) */
FILE *f = fopen("/dev/urandom", "rb");
fread(iv, 1, 32, f);
fclose(f);
```

## File Layout for Integration

```
your_project/
├── include/
│   └── aes_ige_aead.h
├── lib/
│   └── libaes_ige_aead.a
└── src/
    └── your_app.c
```

## Dependencies

None. The library uses only standard C (C99) and requires no external libraries.
