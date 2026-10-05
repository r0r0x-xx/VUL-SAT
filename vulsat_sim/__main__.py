"""VUL-SAT: arma SatelliteCore + PtyLink + telemetría + TUI."""
from __future__ import annotations

import threading
import time

from .satellite_core import SatelliteCore, SatelliteState
from .pty_link import PtyLink
from .telemetry import TelemetryScheduler
from . import tui

CRASH_REBOOT_AFTER_S = 8.0


def main() -> None:
    core = SatelliteCore(SatelliteState())
    link = PtyLink(on_tc=lambda tc: [link.send_tm(f) for f in core.handle_tc(tc)])
    sched = TelemetryScheduler(core, send=link.send_tm)
    stop = threading.Event()

    print(f"[vulsat] PTY satelite en: {link.slave_name}")
    print(f"[vulsat] puerto publicado en .sat_port — Ctrl-C para salir")
    time.sleep(1.0)

    # Envío inicial de STATUS/NAV para que C3 y la TUI no arranquen en
    # blanco hasta el primer ciclo de TelemetryScheduler.due().
    link.send_tm(core.build_status_tm(0))
    link.send_tm(core.build_nav_tm(0))

    t0 = time.monotonic()
    crashed_at = None
    tui.hide_cursor()
    first = True
    # core.tick(dt) trunca con int(dt): llamarlo con el dt chico del loop
    # (~0.1s) dejaría uptime_s congelado en 0. Acumulamos tiempo real y
    # sólo invocamos tick(1.0) cuando pasó un segundo completo (pudiendo
    # ponerse al día con varios ticks si el loop se retrasa).
    last = time.monotonic()
    acc = 0.0
    try:
        while not stop.is_set():
            link.pump_once(timeout=0.1)
            now = time.monotonic()
            acc += now - last
            last = now
            while acc >= 1.0:
                core.tick(1.0)
                acc -= 1.0
            for frame in sched.due(time.monotonic() - t0):
                link.send_tm(frame)
            # auto-reboot tras un crash (PoC 02) para que la demo continue
            if core.state.crashed and crashed_at is None:
                crashed_at = time.monotonic()
            if crashed_at and time.monotonic() - crashed_at > CRASH_REBOOT_AFTER_S:
                core.reboot(); crashed_at = None
            tui.draw(tui.render(core.state), first=first)
            first = False
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        tui.show_cursor()
        link.close()


if __name__ == "__main__":
    main()
