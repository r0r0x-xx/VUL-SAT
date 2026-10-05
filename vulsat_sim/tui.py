"""TUI del satélite emulado: pantalla fija estilo `top`, refresco en el lugar.
Patrón tomado de PWNUAV/pwnuav/tui.py. `render()` es puro y testeable.
"""
from __future__ import annotations

import sys

from .satellite_core import SatelliteState


def orbit_line(angle: float, width: int) -> str:
    pos = int((angle % 360.0) / 360.0 * (width - 1))
    row = ["."] * width
    row[pos] = "o"
    return "".join(row)


def _bar(value: int, width: int = 10) -> str:
    fill = int(value / 255 * width)
    return "[" + "#" * fill + "." * (width - fill) + "]"


def render(state: SatelliteState, width: int = 72) -> str:
    link = "DOWN" if (state.crashed or not state.link_up) else "UP"
    lines = [
        "=" * width,
        "  VUL-SAT  ::  FlatSat EMULADO".ljust(width),
        "=" * width,
        "  ORBITA  " + orbit_line(state.orbit_angle, width - 12),
        "",
        f"  THRUSTER0 {_bar(state.thruster[0])} {state.thruster[0]:3d}    "
        f"THRUSTER1 {_bar(state.thruster[1])} {state.thruster[1]:3d}",
        f"  MODE: {state.mode:<8}  BEACON: {state.beacon_rate_s:>3}s   "
        f"AES: {'ON ' if state.aes_enabled else 'OFF'}   LINK: {link}",
        f"  UPTIME: {state.uptime_s:>5}s   APIDs vistos: "
        + " ".join(f"{a:02X}" for a in sorted(state.seen_apids)),
        "",
    ]
    if state.crashed:
        lines.append("  *** CRASH: mision caida (BROADCAST_MSG underflow) — REBOOT... ***")
    else:
        lines.append("  >> " + (state.last_event or "nominal"))
    lines.append("=" * width)
    return "\n".join(l[:width].ljust(width) for l in lines)


def draw(text: str, first: bool = False) -> None:
    out = ["\033[2J" if first else "", "\033[H"]
    for line in text.split("\n"):
        out.append(line + "\033[K")
    out.append("\033[J")
    sys.stdout.write("\n".join(out))
    sys.stdout.flush()


def hide_cursor() -> None:
    sys.stdout.write("\033[?25l"); sys.stdout.flush()


def show_cursor() -> None:
    sys.stdout.write("\033[?25h\n"); sys.stdout.flush()
