import os
import re
import time
from dataclasses import dataclass
from typing import Optional, List

from .database import get_db

LOOT_DIR = "loot"


def _safe_filename(name: str) -> str:
    """Strip any characters that could cause path traversal or injection."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', name)


@dataclass
class Loot:
    id: Optional[int]
    session_id: str
    loot_type: str
    collected_at: float
    description: Optional[str] = None
    data: Optional[bytes] = None
    filepath: Optional[str] = None

    @classmethod
    def from_row(cls, row) -> "Loot":
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            loot_type=row["loot_type"],
            description=row["description"],
            data=bytes(row["data"]) if row["data"] else None,
            filepath=row["filepath"],
            collected_at=row["collected_at"],
        )


def _ensure_loot_dir() -> str:
    """Create and return the loot directory path."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    return LOOT_DIR


def store_loot(
    session_id: str,
    loot_type: str,
    description: Optional[str] = None,
    data: Optional[bytes] = None,
    filepath: Optional[str] = None,
) -> Loot:
    """
    Persist a loot item to the database.

    If `data` is provided and `filepath` is not set, the raw bytes are saved
    to the loot/ directory automatically and `filepath` is updated to point
    at the written file.
    """
    now = time.time()
    saved_path = filepath

    if data is not None and filepath is None:
        loot_dir = _ensure_loot_dir()
        safe_type = _safe_filename(loot_type)
        safe_sid = _safe_filename(session_id[:8])
        filename = f"{safe_type}_{safe_sid}_{int(now)}.bin"
        candidate = os.path.join(loot_dir, filename)
        # Verify the resolved path stays within the loot directory.
        abs_loot_dir = os.path.abspath(loot_dir)
        abs_candidate = os.path.abspath(candidate)
        if not abs_candidate.startswith(abs_loot_dir + os.sep):
            raise ValueError(f"Refusing to write loot outside loot directory: {abs_candidate}")
        saved_path = abs_candidate
        with open(saved_path, "wb") as fh:
            fh.write(data)

    db = get_db()
    try:
        cursor = db.execute(
            """
            INSERT INTO loot (session_id, loot_type, description, data, filepath, collected_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, loot_type, description, data, saved_path, now),
        )
        db.commit()
    except Exception:
        # Clean up the orphan file if the DB insert failed.
        if saved_path is not None and saved_path != filepath:
            try:
                os.remove(saved_path)
            except OSError:
                pass
        raise

    return Loot(
        id=cursor.lastrowid,
        session_id=session_id,
        loot_type=loot_type,
        description=description,
        data=data,
        filepath=saved_path,
        collected_at=now,
    )


def list_loot(
    session_id: Optional[str] = None,
    loot_type: Optional[str] = None,
) -> List[Loot]:
    """
    List loot items with optional filters.

    Parameters
    ----------
    session_id:
        When provided, restrict results to this session.
    loot_type:
        When provided, restrict results to this loot type.
    """
    db = get_db()

    clauses: list[str] = []
    params: list = []

    if session_id is not None:
        clauses.append("session_id = ?")
        params.append(session_id)
    if loot_type is not None:
        clauses.append("loot_type = ?")
        params.append(loot_type)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = db.execute(
        f"SELECT * FROM loot {where} ORDER BY collected_at DESC",
        params,
    ).fetchall()

    return [Loot.from_row(r) for r in rows]


def get_loot(loot_id: int) -> Optional[Loot]:
    """Fetch a single loot item by primary key."""
    db = get_db()
    row = db.execute("SELECT * FROM loot WHERE id = ?", (loot_id,)).fetchone()
    return Loot.from_row(row) if row else None
