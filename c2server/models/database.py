import atexit
import sqlite3
import os
import threading

_local = threading.local()
_db_path: str = ""

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    username TEXT,
    uid INTEGER,
    pid INTEGER,
    os TEXT DEFAULT 'linux',
    arch TEXT DEFAULT 'amd64',
    in_namespace INTEGER DEFAULT 0,
    interfaces TEXT,
    session_key BLOB NOT NULL,
    client_pubkey BLOB,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    sleep_interval INTEGER DEFAULT 30,
    jitter REAL DEFAULT 0.2,
    status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    type TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    created_at REAL NOT NULL,
    sent_at REAL,
    completed_at REAL
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    session_id TEXT NOT NULL REFERENCES sessions(id),
    output BLOB,
    error TEXT,
    received_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    loot_type TEXT NOT NULL,
    description TEXT,
    data BLOB,
    filepath TEXT,
    collected_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS listeners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    bind_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    options TEXT DEFAULT '{}',
    status TEXT DEFAULT 'stopped',
    started_at REAL
);

CREATE INDEX IF NOT EXISTS idx_tasks_session_status ON tasks(session_id, status);
CREATE INDEX IF NOT EXISTS idx_results_task_id ON results(task_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
"""


def init_db(path: str) -> None:
    """Initialize the database at the given path, creating schema if needed."""
    global _db_path
    _db_path = path

    db_dir = os.path.dirname(path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def get_db() -> sqlite3.Connection:
    """Return a per-thread SQLite connection, creating one if needed."""
    if not _db_path:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            conn = None
            _local.conn = None

    if conn is None:
        conn = sqlite3.connect(_db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        _local.conn = conn

    return conn


def close_db() -> None:
    """Close the per-thread connection if open."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


atexit.register(close_db)
