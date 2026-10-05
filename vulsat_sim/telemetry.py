"""Telemetría periódica del satélite emulado: STATUS, NAV y beacon según
cadencias del firmware real. `due()` es puro (testeable); el loop de
vulsat_sim/__main__.py la usa directamente (ver CRASH_REBOOT_AFTER_S ahí).
"""
from __future__ import annotations

import time
from typing import Callable

from .satellite_core import SatelliteCore

STATUS_PERIOD_S = 14.0
NAV_PERIOD_S = 22.0


class TelemetryScheduler:
    def __init__(self, core: SatelliteCore, send: Callable[[bytes], None],
                 now: Callable[[], float] = time.monotonic) -> None:
        self.core = core
        self.send = send
        self.now = now
        self._seq = 0
        self._last_status = 0.0
        self._last_nav = 0.0

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0x3FFF
        return self._seq

    def due(self, elapsed: float) -> list:
        """Frames vencidos a tiempo `elapsed` (segundos desde t0). No envía."""
        out = []
        if not self.core.is_alive():
            return out
        if elapsed - self._last_status >= STATUS_PERIOD_S:
            self._last_status = elapsed
            out.append(self.core.build_status_tm(self._next_seq()))
        if elapsed - self._last_nav >= NAV_PERIOD_S:
            self._last_nav = elapsed
            out.append(self.core.build_nav_tm(self._next_seq()))
        return out
