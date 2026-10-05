"""Link-state watchdog: the state machine behind the frontend's "effects
monitor" panel.

Runs independent of any specific browser tab, so every connected client (an
operator view, an attack-panel view, a spectator/projector view) agrees on
the same picture. It reacts purely to telemetry *arriving on this backend's
own transport connection* -- not to who sent the command that caused a
reaction -- so it behaves identically whether a reset was triggered by this
tool's own attack panel, a HackRF transmission, or the project's separate
SpaceCAN serial console.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from . import settings

LinkStateName = str  # "connected" | "stale" | "lost"

BroadcastFn = Callable[[dict], Awaitable[None]]


@dataclass
class WatchdogSnapshot:
    state: LinkStateName
    last_telemetry_age_ms: Optional[int]
    secure_link_enabled: bool
    usb_debug_enabled: bool


class LinkWatchdog:
    def __init__(self) -> None:
        self._last_telemetry_at: Optional[float] = None
        self._state: LinkStateName = "lost"
        self._last_uptime_s: Optional[int] = None
        self._secure_link_enabled = settings.ASSUME_SECURE_LINK_ENABLED
        self._usb_debug_enabled = False
        self._last_broadcast_at = 0.0

    # --- called from telemetry_bus as packets are decoded ---

    def record_packet(self) -> None:
        self._last_telemetry_at = time.monotonic()

    def reset(self) -> None:
        """Clears link freshness back to "lost". Called when the operator
        switches the active transport source (see app.py's /api/transport):
        without this, the aggregate link_state only tracks "age since any
        packet last arrived" regardless of which source produced it, so
        switching from a source that was actively receiving (e.g. USB) to
        one that isn't (e.g. radio with no SDR/GNU Radio bridge running)
        kept showing "connected" off the old source's stale freshness
        instead of reflecting that the newly-selected source has nothing
        yet."""
        self._last_telemetry_at = None
        self._state = "lost"

    def record_status(self, fields: dict) -> bool:
        """Feed a decoded STATUS (0x0C) TM's fields. Returns True if this
        reading indicates the board just rebooted (uptime rollback)."""
        uptime_s = fields.get("uptime_s")
        reset_detected = False
        if (
            uptime_s is not None
            and self._last_uptime_s is not None
            and uptime_s < self._last_uptime_s - settings.RESET_UPTIME_TOLERANCE_S
        ):
            reset_detected = True
        if uptime_s is not None:
            self._last_uptime_s = uptime_s

        status_flags = fields.get("status_flags_decoded")
        if status_flags is not None:
            self._secure_link_enabled = bool(status_flags.get("secure_link", self._secure_link_enabled))
            self._usb_debug_enabled = bool(status_flags.get("usb_debug", self._usb_debug_enabled))
        return reset_detected

    def record_aes_config(self, fields: dict) -> None:
        if "secure_link_enabled" in fields:
            self._secure_link_enabled = bool(fields["secure_link_enabled"])

    def record_debug_config(self, fields: dict) -> None:
        if "usb_debug_enabled" in fields:
            self._usb_debug_enabled = bool(fields["usb_debug_enabled"])
        if "secure_link_enabled" in fields:
            self._secure_link_enabled = bool(fields["secure_link_enabled"])

    # --- current AES/debug state, needed by telemetry_bus to know whether
    #     to attempt decryption before decoding a payload ---

    @property
    def payload_is_encrypted(self) -> bool:
        return self._secure_link_enabled and not self._usb_debug_enabled

    def snapshot(self) -> WatchdogSnapshot:
        age_ms = None
        if self._last_telemetry_at is not None:
            age_ms = int((time.monotonic() - self._last_telemetry_at) * 1000)
        return WatchdogSnapshot(
            state=self._state,
            last_telemetry_age_ms=age_ms,
            secure_link_enabled=self._secure_link_enabled,
            usb_debug_enabled=self._usb_debug_enabled,
        )

    def _compute_state(self) -> LinkStateName:
        if self._last_telemetry_at is None:
            return "lost"
        age = time.monotonic() - self._last_telemetry_at
        if age < settings.STALE_AFTER_S:
            return "connected"
        if age < settings.LOST_AFTER_S:
            return "stale"
        return "lost"

    async def run(self, broadcast: BroadcastFn, reset_pulses: "asyncio.Queue[bool]") -> None:
        """Background task: ticks roughly once a second, broadcasts a
        `link_state` message on every state change and at least every
        HEARTBEAT_INTERVAL_S even without one, and forwards one-shot
        `reset_detected` pulses queued by telemetry_bus."""
        while True:
            await asyncio.sleep(1.0)

            while not reset_pulses.empty():
                reset_pulses.get_nowait()
                await broadcast({"type": "link_state", "state": "reset_detected",
                                  "last_telemetry_age_ms": 0, "port": None})

            new_state = self._compute_state()
            now = time.monotonic()
            changed = new_state != self._state
            heartbeat_due = (now - self._last_broadcast_at) >= settings.HEARTBEAT_INTERVAL_S
            self._state = new_state
            if changed or heartbeat_due:
                self._last_broadcast_at = now
                snap = self.snapshot()
                await broadcast({
                    "type": "link_state",
                    "state": snap.state,
                    "last_telemetry_age_ms": snap.last_telemetry_age_ms,
                })
