"""Main context commands -- available when NOT interacting with a session."""

from __future__ import annotations

import argparse
import json
from typing import TYPE_CHECKING, List, Optional

import cmd2

from ..models.database import get_db
from ..models.loot import list_loot
from ..models.session import Session, get_session, list_sessions
from .tables import (
    _compute_session_status,
    listeners_table,
    loot_table,
    sessions_table,
)
from .theme import console

if TYPE_CHECKING:
    from .app import NamespaceC2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _list_listeners() -> list:
    """Fetch all listener rows from the database."""
    db = get_db()
    return db.execute("SELECT * FROM listeners ORDER BY id").fetchall()


def _get_listener(listener_id: int):
    """Fetch a single listener row by ID."""
    db = get_db()
    return db.execute("SELECT * FROM listeners WHERE id = ?", (listener_id,)).fetchone()


def _session_id_completer(app: "NamespaceC2") -> List[str]:
    """Return a list of session ID prefixes for tab completion."""
    try:
        sessions = list_sessions()
        return [s.id[:8] for s in sessions]
    except Exception:
        return []


def _resolve_session_id(partial_id: str) -> Optional[Session]:
    """Resolve a partial session ID to a full Session object."""
    # Try exact match first
    session = get_session(partial_id)
    if session:
        return session
    # Try prefix match
    db = get_db()
    rows = db.execute(
        "SELECT * FROM sessions WHERE id LIKE ? ORDER BY last_seen DESC",
        (partial_id + "%",),
    ).fetchall()
    if len(rows) == 1:
        return Session.from_row(rows[0])
    elif len(rows) > 1:
        console.print(
            f"[warning]Ambiguous session ID '{partial_id}' -- matches {len(rows)} sessions.[/warning]"
        )
        return None
    console.print(f"[error]Session '{partial_id}' not found.[/error]")
    return None


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

_sessions_parser = cmd2.Cmd2ArgumentParser(description="List sessions or interact with one.")
_sessions_parser.add_argument(
    "-i", "--interact",
    metavar="ID",
    default=None,
    help="Enter implant context for the given session ID",
)
_sessions_parser.add_argument(
    "-s", "--status",
    choices=["active", "dormant", "dead"],
    default=None,
    help="Filter sessions by status",
)


def do_sessions(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """List all sessions or interact with one via -i <id>."""
    if args.interact:
        _enter_session(self, args.interact)
        return

    # Fetch all sessions and filter by computed status (not DB column,
    # since "dormant" is never stored in the DB).
    all_sessions = list_sessions()
    if args.status:
        sessions = [s for s in all_sessions if _compute_session_status(s) == args.status]
    else:
        sessions = all_sessions

    if not sessions:
        console.print("  No sessions.", style="dim")
        return
    table = sessions_table(sessions)
    console.print(table)


def _sessions_completer(self, text, line, begidx, endidx):
    """Tab-complete session IDs for the sessions command."""
    return [sid for sid in _session_id_completer(self) if sid.startswith(text)]


# ---------------------------------------------------------------------------
# interact
# ---------------------------------------------------------------------------

_interact_parser = cmd2.Cmd2ArgumentParser(description="Enter implant context for a session.")
_interact_parser.add_argument("session_id", help="Session ID (or prefix)")


def do_interact(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Shortcut to enter implant context: interact <session_id>."""
    _enter_session(self, args.session_id)


def _interact_completer(self, text, line, begidx, endidx):
    """Tab-complete session IDs for the interact command."""
    return [sid for sid in _session_id_completer(self) if sid.startswith(text)]


def _enter_session(app: "NamespaceC2", session_id: str) -> None:
    """Resolve a session and switch to implant context."""
    session = _resolve_session_id(session_id)
    if session is None:
        return
    app.current_session = session
    app._update_prompt()
    app._switch_to_implant_context()
    console.print(
        f"  Interacting with [implant.id]{session.id[:8]}[/implant.id] "
        f"([hostname]{session.hostname or '?'}[/hostname])",
        highlight=False,
    )


# ---------------------------------------------------------------------------
# listeners
# ---------------------------------------------------------------------------

_listeners_parser = cmd2.Cmd2ArgumentParser(description="Manage network listeners.")
_listeners_subparsers = _listeners_parser.add_subparsers(dest="action", help="Listener action")

# listeners list
_listeners_list_parser = _listeners_subparsers.add_parser("list", help="List all listeners")

# listeners start
_listeners_start_parser = _listeners_subparsers.add_parser("start", help="Start a new listener")
_listeners_start_sub = _listeners_start_parser.add_subparsers(dest="listener_type", help="Listener type")

# listeners start https
_ls_https = _listeners_start_sub.add_parser("https", help="Start an HTTPS listener")
_ls_https.add_argument("bind", help="Bind address (e.g. 0.0.0.0)")
_ls_https.add_argument("port", type=int, help="Port number")
_ls_https.add_argument("--cert", default=None, help="Path to TLS certificate")
_ls_https.add_argument("--key", default=None, help="Path to TLS private key")

# listeners start dns
_ls_dns = _listeners_start_sub.add_parser("dns", help="Start a DNS listener")
_ls_dns.add_argument("bind", help="Bind address (e.g. 0.0.0.0)")
_ls_dns.add_argument("port", type=int, help="Port number")
_ls_dns.add_argument("domain", help="DNS domain for C2 communications")

# listeners stop
_listeners_stop_parser = _listeners_subparsers.add_parser("stop", help="Stop a listener")
_listeners_stop_parser.add_argument("listener_id", type=int, help="Listener ID to stop")


def do_listeners(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Manage network listeners: list, start, stop."""
    if args.action is None or args.action == "list":
        rows = _list_listeners()
        if not rows:
            console.print("  No listeners configured.", style="dim")
            return
        table = listeners_table(rows)
        console.print(table)
        return

    if args.action == "start":
        ltype = getattr(args, "listener_type", None)
        if ltype is None:
            console.print("[error]Specify listener type: https or dns[/error]")
            return

        if not (1 <= args.port <= 65535):
            console.print(f"[error]Invalid port {args.port}: must be between 1 and 65535.[/error]")
            return

        options = {}
        if ltype == "https":
            if args.cert:
                options["cert"] = args.cert
            if args.key:
                options["key"] = args.key
        elif ltype == "dns":
            options["domain"] = args.domain

        db = get_db()
        import time
        cursor = db.execute(
            """
            INSERT INTO listeners (type, bind_address, port, options, status, started_at)
            VALUES (?, ?, ?, ?, 'running', ?)
            """,
            (ltype, args.bind, args.port, json.dumps(options), time.time()),
        )
        db.commit()
        lid = cursor.lastrowid

        style = "listener.https" if ltype == "https" else "listener.dns"
        console.print(
            f"  Started [{style}]{ltype.upper()}[/{style}] listener "
            f"[implant.id]#{lid}[/implant.id] on "
            f"[hostname]{args.bind}:{args.port}[/hostname]",
            highlight=False,
        )
        return

    if args.action == "stop":
        row = _get_listener(args.listener_id)
        if row is None:
            console.print(f"[error]Listener #{args.listener_id} not found.[/error]")
            return
        if row["status"] == "stopped":
            console.print(f"[warning]Listener #{args.listener_id} is already stopped.[/warning]")
            return
        db = get_db()
        db.execute(
            "UPDATE listeners SET status = 'stopped' WHERE id = ?",
            (args.listener_id,),
        )
        db.commit()
        console.print(
            f"  Stopped listener [implant.id]#{args.listener_id}[/implant.id].",
            highlight=False,
        )
        return


# ---------------------------------------------------------------------------
# loot
# ---------------------------------------------------------------------------

_loot_parser = cmd2.Cmd2ArgumentParser(description="Browse collected loot.")
_loot_parser.add_argument("-s", "--session", default=None, help="Filter by session ID")
_loot_parser.add_argument("-t", "--type", default=None, dest="loot_type", help="Filter by loot type")


def do_loot(self: "NamespaceC2", args: argparse.Namespace) -> None:
    """Browse collected loot, optionally filtered by session or type."""
    items = list_loot(session_id=args.session, loot_type=args.loot_type)
    if not items:
        console.print("  No loot collected.", style="dim")
        return
    table = loot_table(items)
    console.print(table)


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

def do_generate(self: "NamespaceC2", _args) -> None:
    """Show instructions for generating an implant payload."""
    rows = _list_listeners()
    running = [r for r in rows if r["status"] == "running"]

    console.print()
    console.print("[panel.title]  Implant Generation[/panel.title]")
    console.print()

    if not running:
        console.print(
            "  [warning]No running listeners. Start one first with "
            "'listeners start'.[/warning]"
        )
        console.print()
        return

    console.print("  Active listeners:", style="info")
    for r in running:
        ltype = r["type"]
        style = "listener.https" if ltype == "https" else "listener.dns"
        opts = json.loads(r["options"]) if r["options"] else {}
        console.print(
            f"    [{style}]{ltype.upper()}[/{style}] "
            f"[hostname]{r['bind_address']}:{r['port']}[/hostname]",
            highlight=False,
        )
    console.print()
    console.print("  Build the implant with the server configuration:", style="output")
    console.print()

    for r in running:
        ltype = r["type"]
        opts = json.loads(r["options"]) if r["options"] else {}
        if ltype == "https":
            console.print(
                f"    [dim]$[/dim] [output]cd implant && go build "
                f"-ldflags \"-X main.C2Host={r['bind_address']} "
                f"-X main.C2Port={r['port']} "
                f"-X main.Proto=https\" -o payload .[/output]",
                highlight=False,
            )
        elif ltype == "dns":
            domain = opts.get("domain", "example.com")
            console.print(
                f"    [dim]$[/dim] [output]cd implant && go build "
                f"-ldflags \"-X main.C2Host={r['bind_address']} "
                f"-X main.C2Port={r['port']} "
                f"-X main.Proto=dns "
                f"-X main.Domain={domain}\" -o payload .[/output]",
                highlight=False,
            )
    console.print()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

MAIN_COMMANDS = {
    "sessions":  (do_sessions,  _sessions_parser,  _sessions_completer),
    "interact":  (do_interact,  _interact_parser,   _interact_completer),
    "listeners": (do_listeners, _listeners_parser,  None),
    "loot":      (do_loot,      _loot_parser,       None),
    "generate":  (do_generate,  None,               None),
}


def register_main_commands(app_cls: type) -> None:
    """Attach all main-context commands and their parsers to the app class."""
    for name, (func, parser, completer) in MAIN_COMMANDS.items():
        method_name = f"do_{name}"
        if parser is not None:
            wrapped = _make_cmd2_method(func, parser)
            setattr(app_cls, method_name, wrapped)
        else:
            setattr(app_cls, method_name, func)

        if completer is not None:
            setattr(app_cls, f"complete_{name}", completer)


def _make_cmd2_method(func, parser):
    """Create a cmd2-compatible method wrapped with an argparser."""
    @cmd2.with_argparser(parser)
    def method(self, args):
        return func(self, args)
    method.__doc__ = func.__doc__
    return method
