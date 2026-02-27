"""AES-256-GCM encrypt/decrypt matching Go's cipher.GCM.Seal format."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12  # bytes — matches Go gcm.NonceSize()


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    This matches Go's gcm.Seal(nonce, nonce, plaintext, nil).

    Args:
        key: 32-byte AES-256 key.
        plaintext: Arbitrary-length plaintext bytes.

    Returns:
        nonce || ciphertext+tag  (len = 12 + len(plaintext) + 16)

    Raises:
        ValueError: If key is not 32 bytes.
    """
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes for AES-256, got {len(key)}")

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (tag appended automatically)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext_and_tag


def decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt an AES-256-GCM payload produced by encrypt() or the Go implant.

    Expected input format: nonce (12 bytes) || ciphertext || tag (16 bytes)

    Args:
        key: 32-byte AES-256 key.
        data: Encrypted payload.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key is not 32 bytes or data is too short.
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes for AES-256, got {len(key)}")
    if len(data) < _NONCE_SIZE + 16:
        raise ValueError(
            f"ciphertext too short: expected at least {_NONCE_SIZE + 16} bytes, got {len(data)}"
        )

    nonce = data[:_NONCE_SIZE]
    ciphertext_and_tag = data[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
