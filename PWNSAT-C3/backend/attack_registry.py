"""Canned attack presets for the rehearsal attack panel.

Thin adapter over pwnsat_tools/sim_attack.py's `make_attack()` --
that module already builds the exact raw SPP packet sequence for each named
attack (reset-dos, thruster-control, beacon-flood, broadcast-underflow,
replay, aes-downgrade, gs-handshake-start, etc). This module does not
re-derive any attack payload, it only exposes the same list for the API/UI.
"""
from __future__ import annotations

from typing import List

from . import settings  # noqa: F401
from sim_attack import make_attack

ATTACK_NAMES = [
    "reset-dos",
    "firmware-disclosure",
    "thruster-control",
    "beacon-flood",
    "broadcast-underflow",
    "truncated-spp",
    "flash-block",
    "replay",
    "status-recon",
    "aes-downgrade",
    "mission-mode-abuse",
    "gs-handshake-start",
]

ATTACK_DESCRIPTIONS = {
    "reset-dos": "Unauthenticated RESETC -- reboots the board (finding #16).",
    "firmware-disclosure": "SEND_FW without authentication (finding #21).",
    "thruster-control": "SET_THRUSTER to full power without authentication (finding #17).",
    "beacon-flood": "SET_BEACON_RATE=0 -- floods the downlink (finding #18).",
    "broadcast-underflow": "1-byte BROADCAST_MSG -- integer underflow crash (finding #10, critical).",
    "truncated-spp": "Declared length larger than the real payload (finding #7).",
    "flash-block": "FLASH dump -- exfiltrates the embedded blob and blocks other telemetry (finding #19).",
    "replay": "Sends the exact same PING packet twice (finding #5).",
    "status-recon": "SEND_FW + STATUS + NAV + PAYLOAD_STATUS with no auth (finding #21).",
    "aes-downgrade": "Cleartext AES_CONFIG(0) -- disables the secure link without the key (finding #11).",
    "mission-mode-abuse": "Forces PAYLOAD mode then abuses BROADCAST_MSG as a relay (finding #6).",
    "gs-handshake-start": "Requests a ground-station challenge (setup step for finding #14).",
}


class UnknownAttack(ValueError):
    pass


def build_attack(name: str) -> List[bytes]:
    if name not in ATTACK_NAMES:
        raise UnknownAttack(name)
    return make_attack(name)


def available_attacks() -> list[dict]:
    return [
        {"name": name, "description": ATTACK_DESCRIPTIONS.get(name, "")}
        for name in ATTACK_NAMES
    ]
