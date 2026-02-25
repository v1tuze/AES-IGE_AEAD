# aes_ige_aead — Python binding

CPython C extension for AES-IGE-AEAD authenticated encryption.

## Install

From project root:

```bash
pip install ./python
```

Or:

```bash
cd python
pip install .
```

## Usage

```python
import os
from aes_ige_aead import encrypt, decrypt, KEY_SIZE, IV_SIZE

key = os.urandom(KEY_SIZE)
iv = os.urandom(IV_SIZE)
plaintext = b"Secret message"

ciphertext = encrypt(key=key, iv=iv, plaintext=plaintext)
decrypted = decrypt(key=key, ciphertext=ciphertext)

assert decrypted == plaintext
```

With AAD (Associated Authenticated Data):

```python
aad = b"header: v1"
ciphertext = encrypt(key=key, iv=iv, plaintext=plaintext, aad=aad)
decrypted = decrypt(key=key, ciphertext=ciphertext, aad=aad)
```

## API

| Function | Description |
|----------|-------------|
| `encrypt(key, iv, plaintext, aad=None)` | Returns ciphertext bytes |
| `decrypt(key, ciphertext, aad=None)` | Returns plaintext bytes |
| `encrypt_size(plaintext_len)` | Ciphertext buffer size |
| `decrypt_size(ciphertext_len)` | Max plaintext size |

Constants: `KEY_SIZE` (32), `IV_SIZE` (32), `TAG_SIZE` (16), `CHACHA20_POLY1305_NONCE_SIZE` (12)

**ChaCha20-Poly1305** (RFC 8439):
```python
from aes_ige_aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, CHACHA20_POLY1305_NONCE_SIZE

nonce = os.urandom(CHACHA20_POLY1305_NONCE_SIZE)
ct = chacha20_poly1305_encrypt(key=key, nonce=nonce, plaintext=plaintext)
pt = chacha20_poly1305_decrypt(key=key, ciphertext=ct)
```

Exceptions: `aes_ige_aead.AesIgeAeadError`

## Test

```bash
python test_aes_ige_aead.py
```
