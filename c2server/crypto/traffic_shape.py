"""Traffic shaping utilities matching Go's traffic_shape.go exactly."""

from __future__ import annotations

import os
import secrets
import struct

# Mirrors Go: var PayloadSizeBuckets = []int{512, 1024, 2048, 4096, 8192}
BUCKETS: list[int] = [512, 1024, 2048, 4096, 8192]

_MAX_UINT32 = 0xFFFFFFFF
_HEADER_SIZE = 4  # 4-byte big-endian uint32 length prefix

# Noise padding range: 16..256 bytes (matches Go: 16 + int(lenBuf[0])%241)
_NOISE_MIN = 16
_NOISE_RANGE = 241  # exclusive upper bound for the modulo, giving max 256


def _nearest_bucket(data_len: int) -> int:
    """Return the smallest bucket >= data_len, or round up to next 8192 multiple.

    Mirrors Go nearestBucket().
    """
    for size in BUCKETS:
        if data_len <= size:
            return size
    largest = BUCKETS[-1]
    return ((data_len + largest - 1) // largest) * largest


def shape_payload(data: bytes) -> bytes:
    """Pad data to the nearest size bucket with a 4-byte BE length prefix.

    Format: uint32_BE(len(data)) || data || random_padding

    Mirrors Go ShapePayload(data, 0).

    Args:
        data: Payload to shape.

    Returns:
        Padded payload with length prefix.

    Raises:
        ValueError: If data exceeds 4 GiB.
    """
    if len(data) > _MAX_UINT32:
        raise ValueError("payload exceeds 4 GiB length prefix limit")

    target_size = _nearest_bucket(len(data) + _HEADER_SIZE)

    padded = bytearray(target_size)
    struct.pack_into(">I", padded, 0, len(data))
    padded[_HEADER_SIZE : _HEADER_SIZE + len(data)] = data
    pad_start = _HEADER_SIZE + len(data)
    if pad_start < target_size:
        padded[pad_start:] = os.urandom(target_size - pad_start)

    return bytes(padded)


def unshape_payload(data: bytes) -> bytes:
    """Extract original data from a shape_payload() output.

    Reads the 4-byte BE uint32 length prefix.

    Args:
        data: Shaped payload.

    Returns:
        Original data bytes.

    Raises:
        ValueError: If data is too short or the length header is invalid.
    """
    if len(data) < _HEADER_SIZE:
        raise ValueError("data too short for shape header")

    (orig_len,) = struct.unpack_from(">I", data, 0)
    if orig_len > len(data) - _HEADER_SIZE:
        raise ValueError("invalid shape header length")

    return data[_HEADER_SIZE : _HEADER_SIZE + orig_len]


def add_noise(data: bytes) -> bytes:
    """Prepend 4-byte BE length header and append 16-256 random padding bytes.

    Mirrors Go AddNoise().

    Format: uint32_BE(len(data)) || data || random_padding

    Args:
        data: Payload to add noise to.

    Returns:
        Noisy payload with length prefix.

    Raises:
        ValueError: If data exceeds 4 GiB.
    """
    if len(data) > _MAX_UINT32:
        raise ValueError("payload exceeds 4 GiB length prefix limit")

    # Unbiased random in [16, 256] — uses rejection sampling internally.
    # Go side uses cryptoRandIntn(241) which also avoids modular bias.
    padding_len = _NOISE_MIN + secrets.randbelow(_NOISE_RANGE)

    noise = os.urandom(padding_len)
    result = bytearray(_HEADER_SIZE + len(data) + padding_len)
    struct.pack_into(">I", result, 0, len(data))
    result[_HEADER_SIZE : _HEADER_SIZE + len(data)] = data
    result[_HEADER_SIZE + len(data) :] = noise

    return bytes(result)


def strip_noise(data: bytes) -> bytes:
    """Remove noise padding added by add_noise().

    Reads the 4-byte BE uint32 length prefix.

    Args:
        data: Noisy payload.

    Returns:
        Original data bytes.

    Raises:
        ValueError: If data is too short or the length header is invalid.
    """
    if len(data) < _HEADER_SIZE:
        raise ValueError("data too short for noise header")

    (orig_len,) = struct.unpack_from(">I", data, 0)
    if orig_len > len(data) - _HEADER_SIZE:
        raise ValueError("invalid noise header length")

    return data[_HEADER_SIZE : _HEADER_SIZE + orig_len]
