"""Telemetría periódica del satélite emulado: STATUS, NAV, SENSOR,
GS_STATUS, PAYLOAD_STATUS y MISSION_MODE según cadencias de la spec.
`due()` es puro (testeable); el loop de vulsat_sim/__main__.py la usa
directamente (ver CRASH_REBOOT_AFTER_S ahí).

Cada `_last_*` arranca en `-PERIOD` para que la primera llamada a `due()`
(con `elapsed=0.0`, en el cold-start) dispare un ciclo completo de TODOS
los tipos de TM y el dashboard de C3 no arranque con los paneles vacíos.
"""
from __future__ import annotations

import time
from typing import Callable

from .satellite_core import SatelliteCore

STATUS_PERIOD_S = 5.0
NAV_PERIOD_S = 3.0
SENSOR_PERIOD_S = 6.0
GS_STATUS_PERIOD_S = 4.0
PAYLOAD_STATUS_PERIOD_S = 10.0
MISSION_MODE_PERIOD_S = 10.0

# (nombre del atributo _last_*, periodo, builder) -- recorrido genérico en due()
_SCHEDULE = (
    ("_last_status", STATUS_PERIOD_S, "build_status_tm"),
    ("_last_nav", NAV_PERIOD_S, "build_nav_tm"),
    ("_last_sensor", SENSOR_PERIOD_S, "build_sensor_tm"),
    ("_last_gs_status", GS_STATUS_PERIOD_S, "build_gs_status_tm"),
    ("_last_payload_status", PAYLOAD_STATUS_PERIOD_S, "build_payload_status_tm"),
    ("_last_mission_mode", MISSION_MODE_PERIOD_S, "build_mission_mode_tm"),
)


class TelemetryScheduler:
    def __init__(self, core: SatelliteCore, send: Callable[[bytes], None],
                 now: Callable[[], float] = time.monotonic) -> None:
        self.core = core
        self.send = send
        self.now = now
        self._seq = 0
        for attr, period, _builder in _SCHEDULE:
            setattr(self, attr, -period)  # fuerza disparo inmediato en due(0.0)

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0x3FFF
        return self._seq

    def due(self, elapsed: float) -> list:
        """Frames vencidos a tiempo `elapsed` (segundos desde t0). No envía."""
        out = []
        if not self.core.is_alive():
            return out
        for attr, period, builder_name in _SCHEDULE:
            last = getattr(self, attr)
            if elapsed - last >= period:
                setattr(self, attr, elapsed)
                builder = getattr(self.core, builder_name)
                out.append(builder(self._next_seq()))
        return out
