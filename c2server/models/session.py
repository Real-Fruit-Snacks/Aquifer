import time
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Optional, List

from .database import get_db


@dataclass
class Session:
    id: str
    session_key: bytes
    first_seen: float
    last_seen: float
    hostname: Optional[str] = None
    username: Optional[str] = None
    uid: Optional[int] = None
    pid: Optional[int] = None
    os: str = "linux"
    arch: str = "amd64"
    in_namespace: int = 0
    interfaces: Optional[str] = None
    client_pubkey: Optional[bytes] = None
    sleep_interval: int = 30
    jitter: float = 0.2
    status: str = "active"

    def time_since_last_seen(self) -> str:
        """Return a human-readable string of how long ago the session last checked in."""
        delta = time.time() - self.last_seen
        if delta < 60:
            return f"{int(delta)}s ago"
        elif delta < 3600:
            return f"{int(delta // 60)}m {int(delta % 60)}s ago"
        elif delta < 86400:
            hours = int(delta // 3600)
            minutes = int((delta % 3600) // 60)
            return f"{hours}h {minutes}m ago"
        else:
            days = int(delta // 86400)
            hours = int((delta % 86400) // 3600)
            return f"{days}d {hours}h ago"

    @classmethod
    def from_row(cls, row) -> "Session":
        return cls(
            id=row["id"],
            hostname=row["hostname"],
            username=row["username"],
            uid=row["uid"],
            pid=row["pid"],
            os=row["os"],
            arch=row["arch"],
            in_namespace=row["in_namespace"],
            interfaces=row["interfaces"],
            session_key=bytes(row["session_key"]) if row["session_key"] else b"",
            client_pubkey=bytes(row["client_pubkey"]) if row["client_pubkey"] else None,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            sleep_interval=row["sleep_interval"],
            jitter=row["jitter"],
            status=row["status"],
        )


def create_session(
    session_key: bytes,
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    uid: Optional[int] = None,
    pid: Optional[int] = None,
    os_name: str = "linux",
    arch: str = "amd64",
    in_namespace: int = 0,
    interfaces: Optional[str] = None,
    client_pubkey: Optional[bytes] = None,
    sleep_interval: int = 30,
    jitter: float = 0.2,
    session_id: Optional[str] = None,
) -> Session:
    """Insert a new session record and return the Session dataclass."""
    sid = session_id or str(uuid.uuid4())
    now = time.time()

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO sessions
                (id, hostname, username, uid, pid, os, arch, in_namespace,
                 interfaces, session_key, client_pubkey, first_seen, last_seen,
                 sleep_interval, jitter, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                sid, hostname, username, uid, pid, os_name, arch, in_namespace,
                interfaces, session_key, client_pubkey, now, now,
                sleep_interval, jitter,
            ),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    return Session(
        id=sid,
        hostname=hostname,
        username=username,
        uid=uid,
        pid=pid,
        os=os_name,
        arch=arch,
        in_namespace=in_namespace,
        interfaces=interfaces,
        session_key=session_key,
        client_pubkey=client_pubkey,
        first_seen=now,
        last_seen=now,
        sleep_interval=sleep_interval,
        jitter=jitter,
        status="active",
    )


def get_session(session_id: str) -> Optional[Session]:
    """Fetch a session by ID, or None if not found."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()
    return Session.from_row(row) if row else None


def list_sessions(status: Optional[str] = None) -> List[Session]:
    """List all sessions, optionally filtered by status."""
    db = get_db()
    if status is not None:
        rows = db.execute(
            "SELECT * FROM sessions WHERE status = ? ORDER BY last_seen DESC", (status,)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM sessions ORDER BY last_seen DESC"
        ).fetchall()
    return [Session.from_row(r) for r in rows]


def update_session(session: Session) -> None:
    """Persist all mutable fields of a Session back to the database."""
    db = get_db()
    try:
        db.execute(
            """
            UPDATE sessions SET
                hostname = ?,
                username = ?,
                uid = ?,
                pid = ?,
                os = ?,
                arch = ?,
                in_namespace = ?,
                interfaces = ?,
                client_pubkey = ?,
                last_seen = ?,
                sleep_interval = ?,
                jitter = ?,
                status = ?
            WHERE id = ?
            """,
            (
                session.hostname,
                session.username,
                session.uid,
                session.pid,
                session.os,
                session.arch,
                session.in_namespace,
                session.interfaces,
                session.client_pubkey,
                session.last_seen,
                session.sleep_interval,
                session.jitter,
                session.status,
                session.id,
            ),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise


def update_last_seen(session_id: str) -> None:
    """Stamp the session's last_seen to now."""
    db = get_db()
    try:
        db.execute(
            "UPDATE sessions SET last_seen = ? WHERE id = ?",
            (time.time(), session_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise


def mark_dead(session_id: str) -> None:
    """Set session status to 'dead'."""
    db = get_db()
    try:
        db.execute(
            "UPDATE sessions SET status = 'dead' WHERE id = ?",
            (session_id,),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise
