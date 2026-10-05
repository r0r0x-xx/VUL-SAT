"""Transport abstraction: everything above this layer (decoder, registries,
websocket bus, watchdog, REST routes) only ever sees raw SPP bytes in and
decoded telemetry callbacks out. Swapping how those bytes actually reach the
board (USB serial today, radio via GNU Radio/ZMQ later) means writing a new
class here, nothing else.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Optional

TelemetryCallback = Callable[[bytes], None]


class Transport(ABC):
    """A bidirectional link to the FlatSat: send raw SPP telecommands, get
    raw SPP telemetry packets back through a callback."""

    def __init__(self) -> None:
        self._on_telemetry: Optional[TelemetryCallback] = None

    def on_telemetry(self, callback: TelemetryCallback) -> None:
        """Register the function called with each complete raw SPP telemetry
        packet as soon as it's deframed (before decoding)."""
        self._on_telemetry = callback

    def _emit(self, raw_spp: bytes) -> None:
        if self._on_telemetry is not None:
            self._on_telemetry(raw_spp)

    @abstractmethod
    def connect(self) -> None:
        """Open the underlying link. Raises on failure."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the underlying link. Safe to call even if not connected."""

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @abstractmethod
    def send_tc(self, raw_spp: bytes) -> None:
        """Frame and send one raw SPP telecommand packet."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Short human-readable string identifying this link (port name,
        ZMQ address, etc.) for the status panel."""

    @property
    def supports_tx(self) -> bool:
        """Whether send_tc() can actually deliver commands. True for every
        transport except RX-only ones (radio today -- no TX flowgraph
        exists yet). The frontend uses this to grey out the
        Operations/Attack panels instead of letting the operator click
        buttons that will always fail with a clean-but-pointless error."""
        return True
