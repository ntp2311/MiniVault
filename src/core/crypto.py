from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_bytes(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise exc
