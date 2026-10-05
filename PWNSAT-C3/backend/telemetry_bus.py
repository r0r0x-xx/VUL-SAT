"""Turns raw SPP telemetry packets into websocket JSON messages.

Pipeline for each raw packet handed up by a Transport:
  decode_packet (spp_tools) -> decrypt if needed (pwnsat_crypto) ->
  structured decode (tm_decoder) -> broadcast to every connected client.

Also feeds the link watchdog so the effects-monitor state machine reacts to
telemetry regardless of which client (if any) triggered it.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Set

from fastapi import WebSocket

from . import settings, tm_decoder  # noqa: F401
from pwnsat_crypto import decrypt_payload
from spp_tools import decode_packet

from .watchdog import LinkWatchdog

log = logging.getLogger("pwnsat_c3.telemetry_bus")


class TelemetryBus:
    def __init__(self, watchdog: LinkWatchdog) -> None:
        self._clients: Set[WebSocket] = set()
        self._watchdog = watchdog
        self._reset_pulses: "asyncio.Queue[bool]" = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def reset_pulses(self) -> "asyncio.Queue[bool]":
        return self._reset_pulses

    async def register(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def unregister(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    def on_raw_packet(self, raw_spp: bytes, source: str = "", platform: str = "flatsat") -> None:
        """Called from a Transport's background thread -- must not touch the
        event loop directly, only schedule work onto it. `platform` is the
        operator's current craft selection (see app.py's active_platform) --
        used to decide encryption below (see _handle_packet). NOT `source`:
        "radio" is shared hardware (same RTL-SDR/HackRF, same GNU Radio
        bridge, same 918/916MHz -- PWNCUBE's RF params are identical to
        FlatSat's) that can carry either platform's bytes, so the source
        label alone can't tell you which encryption rules apply -- only
        which platform the operator has selected can. FlatSat callers
        passing "" / omitting source, and the platform default "flatsat",
        keep the exact old behavior."""
        if self._loop is None:
            log.warning("telemetry received before event loop was bound, dropping")
            return
        asyncio.run_coroutine_threadsafe(self._handle_packet(raw_spp, source, platform), self._loop)

    async def _handle_packet(self, raw_spp: bytes, source: str = "", platform: str = "flatsat") -> None:
        self._watchdog.record_packet()
        try:
            packet = decode_packet(raw_spp)
        except ValueError as exc:
            await self.broadcast({"type": "decode_error", "raw_hex": raw_spp.hex(), "reason": str(exc)})
            return

        plain = packet.data
        if platform == "pwncube":
            # PWNCUBE does not encrypt by default (no AES-ECB scheme like
            # FlatSat's) -- the watchdog's payload_is_encrypted flag only
            # makes sense for FlatSat's own STATUS/AES_CONFIG/DEBUG_CONFIG
            # TMs, none of which PWNCUBE has, so it must never gate PWNCUBE
            # packets, regardless of whether they arrived via "cube" (USB)
            # or "radio" (RF) -- this has to be keyed off platform, not
            # source, since a PWNCUBE board transmitting over the shared
            # "radio" source would otherwise still get AES-decrypt attempted
            # on plaintext. Every other platform keeps the exact original
            # logic below, untouched.
            encrypted = False
        else:
            # Secured-format packets (opt-in CCSDS secondary header, PING
            # pilot) always ship in the clear -- see New-firmware worker.cpp's
            # own bypass of secureLinkDecodeInPlace for this exact case.
            # Mirroring that here avoids the same class of bug DEBUG_CONFIG
            # already has: trying to AES-decrypt a payload that was never
            # encrypted just because secure_link happens to be on globally.
            encrypted = self._watchdog.payload_is_encrypted and not packet.secondary_header
        if encrypted and packet.data:
            try:
                plain = decrypt_payload(packet.data)
            except ValueError as exc:
                await self.broadcast({
                    "type": "decode_error",
                    "raw_hex": raw_spp.hex(),
                    "reason": f"decrypt failed: {exc}",
                })
                return

        decoded = tm_decoder.decode(packet.apid, plain, packet.secondary_header_bytes, platform)
        fields = decoded.as_dict() if decoded is not None else None

        # These three feed the watchdog's AES/debug-state tracking, which
        # only means something for FlatSat's actual STATUS/AES_CONFIG/
        # DEBUG_CONFIG TMs -- PWNCUBE shares APID 0x0C (STATUS) with
        # FlatSat, and its status_flags always honestly report
        # secure_link=False. Feeding that into the SAME shared watchdog
        # object would leave FlatSat's own payload_is_encrypted flag
        # clobbered the next time the operator switches back -- so these
        # only run for platform=="flatsat".
        if platform == "flatsat":
            if packet.apid == 0x0C and fields is not None:
                if self._watchdog.record_status(fields):
                    self._reset_pulses.put_nowait(True)
            elif packet.apid == 0x0A and fields is not None:
                self._watchdog.record_aes_config(fields)
            elif packet.apid == 0x10 and fields is not None:
                self._watchdog.record_debug_config(fields)

        # APID 0x0B means two different things depending on platform (see
        # tm_decoder.decode()'s docstring) -- resolve the display name the
        # same way, so the frontend can route on apid_name=="NAV" for
        # PWNCUBE instead of the generic table's "FLASH_READ".
        if packet.apid == 0x0B and platform == "pwncube":
            apid_name = "NAV"
        else:
            apid_name = tm_decoder.APID_TM_NAMES.get(packet.apid, packet.apid_name)

        await self.broadcast({
            "type": "telemetry",
            "apid": packet.apid,
            "apid_name": apid_name,
            "seq": packet.sequence_count,
            "encrypted": encrypted,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "raw_hex": raw_spp.hex(),
            "fields": fields,
        })

    async def command_sent(self, apid_name: str, raw_spp: bytes, framed: bytes, encrypted: bool) -> str:
        correlation_id = f"c-{uuid.uuid4().hex[:8]}"
        await self.broadcast({
            "type": "command_sent",
            "correlation_id": correlation_id,
            "apid_name": apid_name,
            "raw_hex": raw_spp.hex(),
            "framed_hex": framed.hex(),
            "encrypted": encrypted,
        })
        return correlation_id
