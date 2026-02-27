"""Abstract base class for all C2 network listeners."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseListener(ABC):
    """Common interface for all listener types (HTTPS, DNS, etc.).

    Subclasses must implement start() and stop().  The listener_type,
    bind_address, and port attributes are set by the subclass constructor.
    """

    listener_type: str = "base"

    def __init__(self, bind_address: str, port: int) -> None:
        self.bind_address = bind_address
        self.port = port
        self._running: bool = False

    @abstractmethod
    def start(self) -> None:
        """Start the listener.  Must be non-blocking (run in background thread)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the listener and release any bound sockets."""

    def is_running(self) -> bool:
        """Return True if the listener is currently accepting connections."""
        return self._running
