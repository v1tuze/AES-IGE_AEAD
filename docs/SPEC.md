# AES-IGE-AEAD Specification

## 1. Overview

AES-IGE-AEAD is an Authenticated Encryption with Associated Data (AEAD) scheme combining:

- **AES-256-IGE** — Block cipher AES-256 in Infinite Garble Extension (IGE) mode
- **Polynomial MAC** — GHASH-style authentication in GF(2^128)
- **KDF** — Key derivation for separate encryption and MAC keys

## 2. Parameters

| Parameter | Value |
|-----------|-------|
| Master key | 256 bits (32 bytes) |
| IV | 256 bits (32 bytes) |
| Tag | 128 bits (16 bytes) |
| Block size | 128 bits (16 bytes) |

## 3. Ciphertext Format

```
Ciphertext = IV || Ciphertext_CT || Tag
```

- **IV** — 32 bytes, must be unique per encryption (cryptographically random)
- **Ciphertext_CT** — PKCS#7 padded encrypted data
- **Tag** — 16 bytes, authentication tag

## 4. Algorithm Details

### 4.1 Key Derivation (KDF)

From master key K (32 bytes), derive:
- enc_key = HMAC-SHA256(K, 0x01)
- mac_key = HMAC-SHA256(K, 0x02)[0:16]

### 4.2 AES-IGE Mode

IGE uses IV = x0 || y0 (32 bytes). For block i (plaintext xi, ciphertext yi):

- **Encryption:** yi = AES_enc(enc_key, xi ⊕ y_{i-1}) ⊕ x_{i-1}
- **Decryption:** xi = AES_dec(enc_key, yi ⊕ x_{i-1}) ⊕ y_{i-1}

Plaintext is padded with PKCS#7 before encryption.

### 4.3 Polynomial MAC

Polynomial evaluation in GF(2^128) with reduction polynomial:
x^128 + x^7 + x^2 + x + 1 (GCM/GHASH standard)

Authenticated input (padded to 16-byte blocks):
```
AAD (padded) || IV || Ciphertext_CT (padded) || len(AAD) || len(Ciphertext_CT)
```

Evaluation: H = 0; for each block B: H = (H ⊕ B) × K (field multiply by mac_key).

### 4.4 Encrypt-then-MAC

1. Generate/store random IV
2. Encrypt: C = IV || AES_IGE_encrypt(plaintext)
3. Compute Tag = PolyMAC(AAD, IV, C)
4. Output: IV || C || Tag

## 5. Security Properties

- **Confidentiality:** AES-256-IGE
- **Integrity:** Polynomial MAC over IV, AAD, ciphertext
- **Authenticity:** Tag verification rejects tampering
- **Key separation:** Encryption and MAC use independently derived keys

## 6. References

- FIPS 197 — AES
- OpenSSL IGE specification (Ben Laurie, 2006)
- NIST SP 800-38D — GCM (GF(2^128) multiplication)
