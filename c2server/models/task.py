import sqlite3
import time
import json
import uuid
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict

from .database import get_db


@dataclass
class Task:
    id: str
    session_id: str
    type: str
    args: Dict[str, Any]
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    sent_at: Optional[float] = None
    completed_at: Optional[float] = None

    @classmethod
    def from_row(cls, row) -> "Task":
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            type=row["type"],
            args=json.loads(row["args"]) if row["args"] else {},
            status=row["status"],
            created_at=row["created_at"],
            sent_at=row["sent_at"],
            completed_at=row["completed_at"],
        )


@dataclass
class TaskResult:
    id: Optional[int]
    task_id: str
    session_id: str
    output: Optional[bytes]
    error: Optional[str]
    received_at: float

    @classmethod
    def from_row(cls, row) -> "TaskResult":
        return cls(
            id=row["id"],
            task_id=row["task_id"],
            session_id=row["session_id"],
            output=bytes(row["output"]) if row["output"] else None,
            error=row["error"],
            received_at=row["received_at"],
        )


def create_task(
    session_id: str,
    type: str,
    args: Optional[Dict[str, Any]] = None,
    task_id: Optional[str] = None,
) -> Task:
    """Insert a new task and return the Task dataclass."""
    tid = task_id or str(uuid.uuid4())
    now = time.time()
    args_json = json.dumps(args or {})

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO tasks (id, session_id, type, args, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (tid, session_id, type, args_json, now),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    return Task(
        id=tid,
        session_id=session_id,
        type=type,
        args=args or {},
        status="pending",
        created_at=now,
    )


def get_task(task_id: str) -> Optional[Task]:
    """Fetch a single task by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return Task.from_row(row) if row else None


def get_pending_tasks(session_id: str) -> List[Task]:
    """Return all pending tasks for a session, oldest first."""
    db = get_db()
    rows = db.execute(
        """
        SELECT * FROM tasks
        WHERE session_id = ? AND status = 'pending'
        ORDER BY created_at ASC
        """,
        (session_id,),
    ).fetchall()
    return [Task.from_row(r) for r in rows]


def mark_sent(task_id: str) -> None:
    """Transition a task from pending to sent, recording the timestamp."""
    db = get_db()
    try:
        db.execute(
            "UPDATE tasks SET status = 'sent', sent_at = ? WHERE id = ? AND status = 'pending'",
            (time.time(), task_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise


def store_result(
    task_id: str,
    session_id: str,
    output: Optional[bytes] = None,
    error: Optional[str] = None,
) -> TaskResult:
    """Insert a result row and mark the corresponding task completed atomically."""
    now = time.time()
    db = get_db()
    try:
        with db:
            cursor = db.execute(
                """
                INSERT INTO results (task_id, session_id, output, error, received_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (task_id, session_id, output, error, now),
            )
            db.execute(
                "UPDATE tasks SET status = 'completed', completed_at = ? WHERE id = ?",
                (now, task_id),
            )
    except sqlite3.Error:
        raise

    return TaskResult(
        id=cursor.lastrowid,
        task_id=task_id,
        session_id=session_id,
        output=output,
        error=error,
        received_at=now,
    )


def get_results(task_id: str) -> List[TaskResult]:
    """Fetch all results for a given task."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM results WHERE task_id = ? ORDER BY received_at ASC",
        (task_id,),
    ).fetchall()
    return [TaskResult.from_row(r) for r in rows]
