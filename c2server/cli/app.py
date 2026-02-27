"""Main cmd2 application for the Namespace C2 operator console."""

from __future__ import annotations

from typing import List

import cmd2

from .tables import banner
from .theme import console


class NamespaceC2(cmd2.Cmd):
    """Namespace C2 operator console -- cmd2 application with context switching."""

    intro = ""  # Replaced by banner in preloop

    # Track which command set is active
    _CONTEXT_MAIN = "main"
    _CONTEXT_IMPLANT = "implant"

    def __init__(self, ecdh=None, db_path: str = "c2.db", **kwargs):
        # Register commands before super().__init__ so cmd2 sees them
        _register_all_commands()

        # Set these before super().__init__ because cmd2 calls get_all_commands()
        self.ecdh = ecdh  # ECDHKeyExchange instance for the HTTPS listener
        self.db_path = db_path
        self.current_session = None  # When set, we are in implant context
        self._context = self._CONTEXT_MAIN

        super().__init__(
            allow_cli_args=False,
            persistent_history_file="~/.shell_history",
            **kwargs,
        )
        self.prompt = ""  # Set dynamically

        # Disable cmd2's default settable parameters noise
        self.hidden_commands.extend(["edit", "macro", "run_pyscript", "run_script", "shortcuts"])

        # These will be populated by register functions
        self._main_commands: List[str] = []
        self._implant_commands: List[str] = []

        self._update_prompt()

    def preloop(self) -> None:
        """Display banner and server info on startup."""
        console.print(banner())
        info = getattr(self, "_server_info", None)
        if info:
            console.print(f"  Server Public Key: [dim]{info['pub_key']}[/dim]")
            console.print(f"  Database: [dim]{info['db_path']}[/dim]")
            console.print()

    def _update_prompt(self) -> None:
        """Rebuild the prompt string based on context."""
        if self.current_session:
            # ANSI escape: peach for hostname, mauve for separator
            # peach: rgb(250,179,135) -> \033[38;2;250;179;135m
            # mauve: rgb(203,166,247) -> \033[38;2;203;166;247m
            hostname = self.current_session.hostname or self.current_session.id[:8]
            self.prompt = (
                "\033[38;2;250;179;135m"
                f"[{hostname}]"
                "\033[0m"
                "\033[38;2;203;166;247m"
                "\u00bb"
                "\033[0m "
            )
        else:
            # mauve for namespace prompt
            self.prompt = (
                "\033[38;2;203;166;247m"
                "namespace\u00bb"
                "\033[0m "
            )

    def _switch_to_implant_context(self) -> None:
        """Enable implant commands, disable main-only commands."""
        self._context = self._CONTEXT_IMPLANT

    def _switch_to_main_context(self) -> None:
        """Enable main commands, disable implant-only commands."""
        self._context = self._CONTEXT_MAIN

    # ---- Context-aware command gating ------------------------------------

    def default(self, statement: cmd2.Statement) -> None:
        """Handle unknown commands with a helpful message."""
        cmd_name = statement.command if hasattr(statement, "command") else str(statement).split()[0]
        console.print(f"[error]Unknown command: {cmd_name}[/error]")
        console.print("  Type [info]help[/info] for available commands.", highlight=False)

    def get_all_commands(self) -> List[str]:
        """Override to filter commands based on current context."""
        from .main_context import MAIN_COMMANDS
        from .implant_context import IMPLANT_COMMANDS

        all_cmds = super().get_all_commands()
        if self._context == self._CONTEXT_IMPLANT:
            # Hide main-only commands in implant context (except universal ones)
            hidden = set(MAIN_COMMANDS.keys())
            return [c for c in all_cmds if c not in hidden]
        else:
            # Hide implant-only commands in main context
            hidden = set(IMPLANT_COMMANDS.keys())
            return [c for c in all_cmds if c not in hidden]

    def do_exit(self, _args) -> bool:
        """Exit the console."""
        console.print("  Exiting.", style="dim")
        return True

    # Alias quit -> exit
    do_quit = do_exit
    do_EOF = do_exit


_commands_registered = False


def _register_all_commands() -> None:
    """Import and register command sets from both contexts (once)."""
    global _commands_registered
    if _commands_registered:
        return
    from .main_context import register_main_commands
    from .implant_context import register_implant_commands

    register_main_commands(NamespaceC2)
    register_implant_commands(NamespaceC2)
    _commands_registered = True
