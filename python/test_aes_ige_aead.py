#!/usr/bin/env python3
"""Tests for aes_ige_aead Python module."""
import os
import sys

try:
    from aes_ige_aead import encrypt, decrypt, encrypt_size, decrypt_size
    from aes_ige_aead import KEY_SIZE, IV_SIZE, TAG_SIZE, CHACHA20_POLY1305_NONCE_SIZE, AesIgeAeadError
except ImportError as e:
    print("Import failed:", e)
    print("Run: pip install .  from the python/ directory")
    sys.exit(1)


def test_roundtrip():
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plain = b"Hello, AES-IGE-AEAD!"
    ct = encrypt(key=key, iv=iv, plaintext=plain)
    pt = decrypt(key=key, ciphertext=ct)
    assert pt == plain, (pt, plain)
    print("roundtrip OK")


def test_with_aad():
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plain = b"secret"
    aad = b"context"
    ct = encrypt(key=key, iv=iv, plaintext=plain, aad=aad)
    pt = decrypt(key=key, ciphertext=ct, aad=aad)
    assert pt == plain
    print("AAD OK")


def test_auth_fail():
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    ct = encrypt(key=key, iv=iv, plaintext=b"x")
    ct_tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    try:
        decrypt(key=key, ciphertext=ct_tampered)
        assert False, "Should have raised"
    except AesIgeAeadError:
        pass
    print("auth fail OK")


def test_sizes():
    assert encrypt_size(0) == 64
    assert encrypt_size(16) == 80
    assert decrypt_size(64) == 16
    print("sizes OK")


def test_empty():
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    ct = encrypt(key=key, iv=iv, plaintext=b"")
    pt = decrypt(key=key, ciphertext=ct)
    assert pt == b""
    print("empty OK")


def test_chacha20_poly1305():
    from aes_ige_aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

    key = os.urandom(KEY_SIZE)
    nonce = os.urandom(CHACHA20_POLY1305_NONCE_SIZE)
    plain = b"ChaCha20-Poly1305"
    ct = chacha20_poly1305_encrypt(key=key, nonce=nonce, plaintext=plain)
    pt = chacha20_poly1305_decrypt(key=key, ciphertext=ct)
    assert pt == plain
    print("chacha20_poly1305 OK")


def main():
    print("Testing aes_ige_aead...")
    test_roundtrip()
    test_with_aad()
    test_auth_fail()
    test_sizes()
    test_empty()
    test_chacha20_poly1305()
    print("All OK")


if __name__ == "__main__":
    main()
