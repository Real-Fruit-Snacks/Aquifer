"""Rich table formatters and display helpers for the Namespace C2 console."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .theme import MOCHA

if TYPE_CHECKING:
    from ..models.loot import Loot
    from ..models.session import Session
    from ..models.task import Task


def _format_ts(ts: Optional[float]) -> str:
    """Format a unix timestamp into a compact datetime string (UTC)."""
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _short_uuid(uid: str) -> str:
    """Return first 8 chars of a UUID."""
    return uid[:8] if uid else "-"


def _status_style(status: str) -> str:
    """Map a session status string to a Rich style name."""
    mapping = {
        "active": "session.active",
        "dormant": "session.dormant",
        "dead": "session.dead",
    }
    return mapping.get(status, "dim")


def _compute_session_status(session: "Session") -> str:
    """Derive display status from last_seen relative to sleep_interval.

    - active:  last seen within 2x the sleep interval
    - dormant: last seen within 10x the sleep interval
    - dead:    last seen beyond 10x the sleep interval
    """
    if session.status == "dead":
        return "dead"
    delta = time.time() - session.last_seen
    interval = max(session.sleep_interval, 1)
    if delta > interval * 10:
        return "dead"
    elif delta > interval * 2:
        return "dormant"
    return "active"


def sessions_table(sessions: List["Session"]) -> Table:
    """Build a Rich table listing sessions."""
    table = Table(
        title="Sessions",
        border_style="table.border",
        header_style="table.header",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("ID", style="implant.id", min_width=10)
    table.add_column("Hostname", style="hostname")
    table.add_column("User", min_width=8)
    table.add_column("PID", justify="right")
    table.add_column("OS")
    table.add_column("Last Seen", style="timestamp")
    table.add_column("Status", justify="center")

    for s in sessions:
        display_status = _compute_session_status(s)

        # Color the user field based on uid
        if s.uid == 0 or s.username == "root":
            user_text = Text(s.username or "-", style="user.root")
        else:
            user_text = Text(s.username or "-", style="user.normal")

        status_text = Text(display_status, style=_status_style(display_status))

        table.add_row(
            _short_uuid(s.id),
            escape(s.hostname or "-"),
            user_text,
            str(s.pid) if s.pid is not None else "-",
            escape(s.os or "-"),
            s.time_since_last_seen(),
            status_text,
        )

    return table


def tasks_table(tasks: List["Task"]) -> Table:
    """Build a Rich table listing tasks."""
    table = Table(
        title="Tasks",
        border_style="table.border",
        header_style="table.header",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("ID", style="implant.id", min_width=10)
    table.add_column("Type", style="info")
    table.add_column("Args", max_width=40)
    table.add_column("Status", justify="center")
    table.add_column("Created", style="timestamp")
    table.add_column("Completed", style="timestamp")

    for t in tasks:
        args_str = str(t.args) if t.args else "-"
        if len(args_str) > 40:
            args_str = args_str[:37] + "..."

        # Color-code task status
        if t.status == "completed":
            st = Text(t.status, style="session.active")
        elif t.status == "pending":
            st = Text(t.status, style="session.dormant")
        elif t.status == "sent":
            st = Text(t.status, style="info")
        else:
            st = Text(t.status, style="dim")

        table.add_row(
            _short_uuid(t.id),
            escape(t.type),
            escape(args_str),
            st,
            _format_ts(t.created_at),
            _format_ts(t.completed_at),
        )

    return table


def results_panel(task_type: str, output: str, error: str) -> Panel:
    """Build a Rich panel displaying task output/error."""
    content_parts: list = []

    if output:
        # Use Syntax highlighting for shell-like output
        syn = Syntax(
            output,
            "text",
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        )
        content_parts.append(syn)

    if error:
        err_text = Text(f"\n[stderr]\n{error}", style="error")
        content_parts.append(err_text)

    if not content_parts:
        content_parts.append(Text("(no output)", style="dim"))

    # Rich Panel expects a single renderable; use a group if multiple
    from rich.console import Group

    body = Group(*content_parts) if len(content_parts) > 1 else content_parts[0]

    return Panel(
        body,
        title=f"Result: {escape(task_type)}",
        border_style="panel.border",
        title_align="left",
        padding=(1, 2),
    )


def listeners_table(listeners: list) -> Table:
    """Build a Rich table listing active listeners.

    Each element in *listeners* should be a sqlite3.Row or dict-like with keys:
    id, type, bind_address, port, status, options.
    """
    table = Table(
        title="Listeners",
        border_style="table.border",
        header_style="table.header",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("ID", justify="right", style="implant.id")
    table.add_column("Type")
    table.add_column("Bind", style="hostname")
    table.add_column("Port", justify="right")
    table.add_column("Status", justify="center")

    for ln in listeners:
        ltype = ln["type"] if hasattr(ln, "__getitem__") else getattr(ln, "type", "?")
        type_style = "listener.https" if ltype == "https" else "listener.dns"

        status_val = (
            ln["status"] if hasattr(ln, "__getitem__") else getattr(ln, "status", "?")
        )
        if status_val == "running":
            status_text = Text(status_val, style="session.active")
        elif status_val == "stopped":
            status_text = Text(status_val, style="session.dead")
        else:
            status_text = Text(status_val, style="dim")

        lid = ln["id"] if hasattr(ln, "__getitem__") else getattr(ln, "id", "?")
        bind = (
            ln["bind_address"]
            if hasattr(ln, "__getitem__")
            else getattr(ln, "bind_address", "?")
        )
        port = ln["port"] if hasattr(ln, "__getitem__") else getattr(ln, "port", "?")

        table.add_row(
            str(lid),
            Text(ltype, style=type_style),
            str(bind),
            str(port),
            status_text,
        )

    return table


def loot_table(loot: List["Loot"]) -> Table:
    """Build a Rich table listing collected loot."""
    table = Table(
        title="Loot",
        border_style="table.border",
        header_style="table.header",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("ID", justify="right", style="implant.id")
    table.add_column("Session", style="implant.id")
    table.add_column("Type", style="info")
    table.add_column("Description")
    table.add_column("Size", justify="right")
    table.add_column("Collected", style="timestamp")

    for item in loot:
        size_str = "-"
        if item.data is not None:
            size_bytes = len(item.data)
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes / 1024:.1f} KB"
            else:
                size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
        elif item.filepath:
            size_str = "(file)"

        table.add_row(
            str(item.id) if item.id is not None else "-",
            _short_uuid(item.session_id),
            escape(item.loot_type),
            escape(item.description or "-"),
            size_str,
            _format_ts(item.collected_at),
        )

    return table


def session_info_panel(session: "Session") -> Panel:
    """Build a Rich panel showing detailed session information."""
    rows: list[str] = []

    def _add(label: str, value: str, style: str = "output") -> None:
        # value must already be escaped before calling _add
        rows.append(f"[key]{label + ':':<16}[/key] [{style}]{value}[/{style}]")

    _add("Session ID", escape(session.id), "implant.id")
    _add("Hostname", escape(session.hostname or "-"), "hostname")

    user_style = "user.root" if (session.uid == 0 or session.username == "root") else "user.normal"
    _add("Username", escape(session.username or "-"), user_style)
    _add("UID", escape(str(session.uid) if session.uid is not None else "-"))
    _add("PID", escape(str(session.pid) if session.pid is not None else "-"))
    _add("OS / Arch", escape(f"{session.os} / {session.arch}"))
    _add("Namespace", "Yes" if session.in_namespace else "No")

    if session.interfaces:
        _add("Interfaces", escape(session.interfaces))

    _add("Sleep", f"{session.sleep_interval}s (+/- {session.jitter * 100:.0f}% jitter)")
    _add("First Seen", _format_ts(session.first_seen), "timestamp")
    _add("Last Seen", f"{escape(session.time_since_last_seen())} ({_format_ts(session.last_seen)})", "timestamp")

    display_status = _compute_session_status(session)
    _add("Status", display_status, _status_style(display_status))

    body = Text.from_markup("\n".join(rows))

    return Panel(
        body,
        title=f"Session {_short_uuid(session.id)}",
        border_style="panel.border",
        title_align="left",
        padding=(1, 2),
    )


def banner() -> str:
    """Return the ASCII art startup banner with Catppuccin colors."""
    mauve = MOCHA["mauve"]
    lavender = MOCHA["lavender"]
    overlay = MOCHA["overlay1"]

    lines = [
        f"[{mauve}]",
        f"    [{lavender}]╔═══════════════════════════════════════╗[/{lavender}]",
        f"    [{lavender}]║[/{lavender}]          [{mauve}]n a m e s p a c e[/{mauve}]            [{lavender}]║[/{lavender}]",
        f"    [{lavender}]║[/{lavender}]                [{mauve}]C 2[/{mauve}]                    [{lavender}]║[/{lavender}]",
        f"    [{lavender}]╚═══════════════════════════════════════╝[/{lavender}]",
        f"[/{mauve}]",
        f"    [{overlay}]Type 'help' for available commands.[/{overlay}]",
        "",
    ]
    return "\n".join(lines)
