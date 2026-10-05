"""Builds legitimate telecommand packets for the operations panel.

Reuses the firmware-matching payload logic already written in
pwnsat_tools/usb_tc_send.py (`build_wire_payload`, `APID_NAMES`)
instead of re-deriving per-APID byte layouts here. That includes the
firmware's own quirks (e.g. a 1-byte payload gets padded to 2 bytes, or the
firmware's parser silently drops it -- see finding #9 in FlatSat's own
findings catalog) -- this tool reproduces real firmware behavior, it does
not "fix" it.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict

from . import settings  # noqa: F401
from spp_tools import SEC_HEADER_LEN, build_tc
from usb_tc_send import APID_NAMES, build_wire_payload

DEFAULT_ARGS: Dict[str, Any] = {
    "payload_hex": None,
    "encrypt": "on",
    "thruster_id": 0,
    "power": 80,
    "seconds": 1,
    "frequency": 0x0394,
    "message": "Pwnsat",
    "mission_mode": 1,
    "aes_mode": 0,
    "debug_mode": 0,
    "gs_comm_mode": 0,
    "handshake": "start",
    "challenge": None,
    "auth_key": settings.DEFAULT_GS_AUTH_KEY,
    "offset": 0,
    "read_length": 32,
    "window_id": settings.DEFAULT_FLASH_WINDOW_ID,
    "unlock_tag": settings.DEFAULT_FLASH_UNLOCK_TAG,
    # gps-override (PWNCUBE only, debug hook) -- defaults match this
    # repo's own ground-station demo coordinates (Las Vegas), same ones the
    # GS-auth-spoofing attack script and GS_STATUS's gate use, so the
    # out-of-the-box default already lands at distance_m=0.
    "gps_lat_deg": 36.1699,
    "gps_lon_deg": -115.1398,
    "gps_alt_m": 600.0,
    "gps_sats": 8,
}


class UnknownCommand(ValueError):
    pass


# Counter for the secured-PING pilot's secondary header -- a plain,
# monotonic tag, not used for any freshness/replay validation (that part
# isn't implemented). Lives here rather than per-request so it actually
# increments across calls, mirroring app.py's own _seq_counter pattern.
_secured_ping_counter = 0


def build_command(
    command: str,
    args: Dict[str, Any] | None,
    encrypt: bool,
    seq: int,
    secured: bool = False,
) -> bytes:
    """Build one raw SPP telecommand packet for `command` (one of
    usb_tc_send.APID_NAMES's keys: ping, reset, fw, thruster, beacon,
    broadcast, flash, aes, flash-read, status, mode, nav, payload-status,
    debug, gs-mode, gs-auth, gs-status, gps-override).

    `secured=True` (ping only, for now) builds the opt-in CCSDS secondary
    header format instead -- see New-firmware spp_tc_build_packet_secured()
    and worker.cpp's commandHandlerInternal. No crypto/security semantics
    implemented yet, so this always ships in the clear regardless of
    `encrypt`, matching the firmware's own bypass of secureLinkDecodeInPlace
    for this exact case.
    """
    if command not in APID_NAMES:
        raise UnknownCommand(command)
    if secured and command != "ping":
        raise UnknownCommand(f"{command} (secured format only implemented for ping)")

    if secured:
        global _secured_ping_counter
        _secured_ping_counter += 1
        sec_header_bytes = (_secured_ping_counter & 0xFFFFFFFF).to_bytes(SEC_HEADER_LEN, "big")
        return build_tc(APID_NAMES[command], b"", seq, sec_header_bytes)

    merged = dict(DEFAULT_ARGS)
    merged.update(args or {})
    merged["command"] = command
    merged["encrypt"] = "on" if encrypt else "off"
    ns = SimpleNamespace(**merged)

    payload = build_wire_payload(ns)
    return build_tc(APID_NAMES[command], payload, seq)


def available_commands() -> list[str]:
    return sorted(APID_NAMES)
