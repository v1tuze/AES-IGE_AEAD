# Deoxys AEAD

Deoxys is a CAESAR competition finalist (winner in the "in-depth security" portfolio). It uses an AES-based tweakable block cipher (Deoxys-BC) and provides two modes:

- **Deoxys-I**: Nonce-respecting, single-pass. Nonce must never be reused.
- **Deoxys-II**: Nonce-misuse resistant, two-pass. Maintains security even if nonce is reused.

## Implemented Variants

| Variant | Key | Nonce | Block Cipher |
|---------|-----|-------|--------------|
| Deoxys-I-128-128 | 16 B | 8 B | Deoxys-BC-256 |
| Deoxys-I-256-128 | 32 B | 8 B | Deoxys-BC-384 |
| Deoxys-II-128-128 | 16 B | 15 B | Deoxys-BC-256 |
| Deoxys-II-256-128 | 32 B | 15 B | Deoxys-BC-384 |

**Implemented:** Deoxys-I-128, Deoxys-I-256, Deoxys-II-128, Deoxys-II-256.

## Ciphertext Format

```
Ciphertext || Tag (16 bytes)
```

No nonce in output — caller must store/transmit it separately.

## Deoxys-BC

Internal tweakable block cipher based on the TWEAKEY framework:

- **Deoxys-BC-256**: 256-bit tweakey (key + tweak), 14 rounds
- **Deoxys-BC-384**: 384-bit tweakey, 16 rounds

Uses AES round function (SubBytes, ShiftRows, MixColumns) with a custom tweakey schedule (LFSR-based).

## References

- [Deoxys website](https://sites.google.com/view/deoxyscipher)
- CAESAR competition submission
- [RustCrypto AEADs](https://github.com/RustCrypto/AEADs/tree/master/deoxys)
