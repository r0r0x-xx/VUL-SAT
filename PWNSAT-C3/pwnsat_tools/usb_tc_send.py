#!/usr/bin/env python3
"""Send framed Pwnsat SPP telecommands over the USBRadioLink CDC endpoint."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import serial

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from pwnsat_crypto import decrypt_payload, encrypt_payload
from spp_tools import SEC_HEADER_LEN, decode_packet, hexdump, print_packet, build_tc


APID_NAMES = {
    "ping": 0x01,
    "reset": 0x02,
    "fw": 0x03,
    "thruster": 0x04,
    "beacon": 0x05,
    "broadcast": 0x06,
    "flash": 0x07,
    "aes": 0x0A,
    "flash-read": 0x0B,
    "status": 0x0C,
    "mode": 0x0D,
    "nav": 0x0E,
    "payload-status": 0x0F,
    "debug": 0x10,
    "gs-mode": 0x11,
    "gs-auth": 0x12,
    "gs-status": 0x13,
    # PWNCUBE-only (debug hook) -- shares APID 0x0A with FlatSat's
    # "aes" above (different meaning per platform, same collision already
    # documented for 0x0A/0x0B elsewhere in this repo's decoders). A
    # distinct dict key here, so this does not touch "aes"/FlatSat at all.
    "gps-override": 0x0A,
}

DEFAULT_FLASH_WINDOW_ID = 0xA5
DEFAULT_FLASH_UNLOCK_TAG = 0xC35A
DEFAULT_GS_AUTH_KEY = 0xC0DEFACE


def parse_hex_bytes(value: str) -> bytes:
    cleaned = value.replace(" ", "").replace(":", "").replace(",", "")
    if len(cleaned) % 2 != 0:
        raise argparse.ArgumentTypeError("hex payload must contain complete bytes")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def frame_usb(raw_spp: bytes) -> bytes:
    return b"\xAA\x55" + len(raw_spp).to_bytes(2, "big") + raw_spp


def compute_gs_response(challenge: int, auth_key: int) -> int:
    return (challenge ^ auth_key) & 0xFFFFFFFF


def build_logical_payload(args: argparse.Namespace) -> bytes:
    if args.payload_hex is not None:
        return args.payload_hex

    if args.command == "thruster":
        return bytes([args.thruster_id & 0xFF, args.power & 0xFF])
    if args.command == "beacon":
        return bytes([args.seconds & 0xFF])
    if args.command == "broadcast":
        return args.frequency.to_bytes(2, "big") + args.message.encode()
    if args.command == "aes":
        return bytes([args.aes_mode & 0xFF])
    if args.command == "flash-read":
        return (
            bytes([args.window_id & 0xFF])
            + args.offset.to_bytes(2, "little")
            + bytes([args.read_length & 0xFF])
            + args.unlock_tag.to_bytes(2, "big")
        )
    if args.command == "mode":
        return bytes([args.mission_mode & 0xFF])
    if args.command == "debug":
        return bytes([args.debug_mode & 0xFF])
    if args.command == "gs-mode":
        return bytes([args.gs_comm_mode & 0xFF])
    if args.command == "gs-auth":
        if args.handshake == "start":
            return b"\x00"
        response = compute_gs_response(args.challenge, args.auth_key)
        return bytes([0x01]) + response.to_bytes(4, "big")
    if args.command == "gps-override":
        # PWNCUBE's SPP_APID_TC_GPS_OVERRIDE handler (command_service.c):
        # latE7(i32 LE) + lonE7(i32 LE) + altCm(i32 LE) + sats(u8), 13 bytes
        # total -- same fixed-point encoding FlatSat's own GPS_OVERRIDE used.
        lat_e7 = int(round(args.gps_lat_deg * 1e7))
        lon_e7 = int(round(args.gps_lon_deg * 1e7))
        alt_cm = int(round(args.gps_alt_m * 100))
        return (
            (lat_e7 & 0xFFFFFFFF).to_bytes(4, "little")
            + (lon_e7 & 0xFFFFFFFF).to_bytes(4, "little")
            + (alt_cm & 0xFFFFFFFF).to_bytes(4, "little")
            + bytes([args.gps_sats & 0xFF])
        )

    return b""


def build_wire_payload(args: argparse.Namespace) -> bytes:
    payload = build_logical_payload(args)
    if args.encrypt == "on":
        return encrypt_payload(payload)
    if len(payload) == 1:
        # Current firmware only copies payload bytes when the SPP length field is > 0.
        return payload + b"\x00"
    return payload


def expected_response_is_encrypted(args: argparse.Namespace) -> bool:
    if getattr(args, "secured", False):
        # Secured-format pilot (PING only): always cleartext, independent of
        # --encrypt. See New-firmware/worker.cpp's commandHandlerInternal,
        # which bypasses secureLinkDecodeInPlace for this exact case -- no
        # crypto/security semantics implemented yet, just the CCSDS
        # secondary-header structure.
        return False
    if args.command == "aes":
        return bool(args.aes_mode)
    if args.command == "debug":
        return False
    return args.encrypt == "on"


def iter_usb_sync_packets(stream: bytes) -> tuple[list[bytes], bytes]:
    packets: list[bytes] = []
    offset = 0

    while offset < len(stream):
        if stream[offset] != 0xAA:
            offset += 1
            continue
        if len(stream) - offset < 7:
            break

        length_field = int.from_bytes(stream[offset + 5 : offset + 7], "big")
        total = 1 + 6 + length_field + 1
        if len(stream) - offset < total:
            break

        packets.append(stream[offset + 1 : offset + total])
        offset += total

    return packets, stream[offset:]


def resolve_payload(raw_spp: bytes, encrypted: bool) -> tuple[object, bytes | None, str | None]:
    packet = decode_packet(raw_spp)
    if not packet.data:
        return packet, b"", None

    if encrypted:
        try:
            plain = decrypt_payload(packet.data)
        except ValueError as exc:
            return packet, None, str(exc)
        return packet, plain, None
    return packet, packet.data, None


def print_gs_access_summary(payload: bytes) -> None:
    if len(payload) < 13 or payload[0] != 0x01:
        return

    phase = payload[1]
    auth_state = payload[2]
    gs_status = payload[3]
    gps_status = payload[4]
    challenge = int.from_bytes(payload[5:9], "little")
    session_remaining = int.from_bytes(payload[9:11], "little")
    challenge_remaining = int.from_bytes(payload[11:13], "little")

    phase_name = {0: "start", 1: "finish"}.get(phase, f"0x{phase:02X}")
    auth_name = {
        0: "challenge-issued",
        1: "accepted",
        2: "rejected",
        3: "challenge-missing",
    }.get(auth_state, f"0x{auth_state:02X}")

    print()
    print(
        "[GS ACCESS] "
        f"phase={phase_name} auth_state={auth_name} gs_status=0x{gs_status:02X} "
        f"gps_status=0x{gps_status:02X} challenge=0x{challenge:08X} "
        f"session_s={session_remaining} challenge_s={challenge_remaining}"
    )


def print_payload_view(raw_spp: bytes, encrypted: bool) -> None:
    packet, payload, error = resolve_payload(raw_spp, encrypted)
    if payload == b"":
        print()
        print("[DATA]")
        print("(empty)")
        return
    if error is not None:
        print()
        print(f"[DECRYPT ERROR] {error}")
        return

    assert payload is not None
    print()
    print("[DECRYPTED DATA]" if encrypted else "[DATA]")
    print(hexdump(payload))
    if packet.apid == 0x012:
        print_gs_access_summary(payload)


def print_received_packets(received: bytes, encrypted: bool) -> None:
    packets, trailing = iter_usb_sync_packets(received)

    if not packets:
        print("[received bytes]")
        print(received.hex())
        print("no complete 0xAA-synchronized telemetry packets decoded")
        return

    print("[received bytes]")
    print(received.hex())

    for index, raw_spp in enumerate(packets, start=1):
        print()
        print(f"[received packet {index}]")
        print_packet(raw_spp)
        print_payload_view(raw_spp, encrypted)

    if trailing:
        print()
        print("[trailing bytes]")
        print(trailing.hex())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and send a framed SPP telecommand over USB."
    )
    parser.add_argument("--port", required=True, help="USBRadioLink serial port")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument(
        "--command",
        choices=sorted(APID_NAMES),
        required=True,
        help="telecommand preset to build",
    )
    parser.add_argument("--payload-hex", type=parse_hex_bytes)
    parser.add_argument("--seq", type=int, default=1)
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--thruster-id", type=int, default=0)
    parser.add_argument("--power", type=int, default=80)
    parser.add_argument("--seconds", type=int, default=1)
    parser.add_argument("--frequency", type=lambda value: int(value, 0), default=0x0394)
    parser.add_argument("--message", default="Pwnsat")
    parser.add_argument(
        "--mission-mode",
        type=int,
        choices=[0, 1, 2, 3, 4],
        default=1,
        help="0 safe, 1 nominal, 2 payload, 3 science, 4 contingency",
    )
    parser.add_argument(
        "--aes-mode",
        type=int,
        choices=[0, 1],
        default=0,
        help="0 disables link AES, 1 enables it",
    )
    parser.add_argument(
        "--debug-mode",
        type=int,
        choices=[0, 1],
        default=0,
        help="0 disables USB debug mode, 1 enables it",
    )
    parser.add_argument(
        "--gs-comm-mode",
        type=int,
        choices=[0, 1],
        default=0,
        help="0 disables ground station mode, 1 enables it",
    )
    parser.add_argument(
        "--handshake",
        choices=["start", "finish"],
        default="start",
        help="gs-auth mode: request a challenge or answer it",
    )
    parser.add_argument(
        "--challenge",
        type=lambda value: int(value, 0),
        help="challenge value returned by gs-auth --handshake start",
    )
    parser.add_argument(
        "--auth-key",
        type=lambda value: int(value, 0),
        default=DEFAULT_GS_AUTH_KEY,
        help="shared ground-station handshake key used by gs-auth finish",
    )
    parser.add_argument("--offset", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--read-length", type=int, default=32)
    parser.add_argument(
        "--window-id",
        type=lambda value: int(value, 0),
        default=DEFAULT_FLASH_WINDOW_ID,
    )
    parser.add_argument(
        "--unlock-tag",
        type=lambda value: int(value, 0),
        default=DEFAULT_FLASH_UNLOCK_TAG,
    )
    parser.add_argument(
        "--gps-lat-deg", type=float, default=36.1699,
        help="gps-override: fake latitude in degrees (default: this repo's ground-station demo coordinates, Las Vegas)",
    )
    parser.add_argument(
        "--gps-lon-deg", type=float, default=-115.1398,
        help="gps-override: fake longitude in degrees",
    )
    parser.add_argument(
        "--gps-alt-m", type=float, default=600.0,
        help="gps-override: fake altitude in meters",
    )
    parser.add_argument(
        "--gps-sats", type=int, default=8,
        help="gps-override: fake satellite count",
    )
    parser.add_argument("--read-seconds", type=float, default=1.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--secured",
        action="store_true",
        help=(
            "ping only: build the opt-in secondary-header format instead of "
            "the plain packet (New-firmware spp_tc_build_packet_secured). "
            "No crypto/security implemented yet -- always sent in the "
            "clear, independent of --encrypt."
        ),
    )
    parser.add_argument(
        "--sec-counter",
        type=lambda value: int(value, 0),
        default=1,
        help="4-byte counter value to put in the secondary header (--secured)",
    )
    args = parser.parse_args()

    if args.command == "gs-auth" and args.handshake == "finish" and args.challenge is None:
        parser.error("--challenge is required with --command gs-auth --handshake finish")
    if args.secured and args.command != "ping":
        parser.error("--secured is only implemented for --command ping so far")

    if args.secured:
        sec_header_bytes = (args.sec_counter & 0xFFFFFFFF).to_bytes(SEC_HEADER_LEN, "big")
        raw_spp = build_tc(APID_NAMES[args.command], b"", args.seq, sec_header_bytes)
    else:
        payload = build_wire_payload(args)
        raw_spp = build_tc(APID_NAMES[args.command], payload, args.seq)
    framed = frame_usb(raw_spp)

    if args.command == "gs-auth" and args.handshake == "finish":
        response = compute_gs_response(args.challenge, args.auth_key)
        print("[gs-auth]")
        print(
            f"challenge=0x{args.challenge:08X} auth_key=0x{args.auth_key:08X} "
            f"response=0x{response:08X}"
        )
        print()

    print("[raw SPP]")
    print(raw_spp.hex())
    print_packet(raw_spp)
    print()
    print("[USB framed]")
    print(framed.hex())

    if args.dry_run:
        return 0

    with serial.Serial(args.port, args.baud, timeout=0.1) as ser:
        time.sleep(0.2)
        ser.write(framed)
        ser.flush()
        deadline = time.time() + args.read_seconds
        received = bytearray()
        while time.time() < deadline:
            chunk = ser.read(4096)
            if chunk:
                received.extend(chunk)

    print()
    if received:
        print_received_packets(bytes(received), expected_response_is_encrypted(args))
    else:
        print("[received bytes]")
        print("no bytes received before timeout")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
