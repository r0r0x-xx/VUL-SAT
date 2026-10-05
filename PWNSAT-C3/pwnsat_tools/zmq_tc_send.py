#!/usr/bin/env python3
"""Send Pwnsat SPP telecommands to a GNU Radio ZMQ message source."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import pmt
import zmq

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from spp_tools import build_tc, print_packet
from usb_tc_send import (
    APID_NAMES,
    DEFAULT_FLASH_UNLOCK_TAG,
    DEFAULT_FLASH_WINDOW_ID,
    DEFAULT_GS_AUTH_KEY,
    build_wire_payload,
    compute_gs_response,
    parse_hex_bytes,
)


DEFAULT_ENDPOINT = "tcp://192.168.0.21:5007"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build an SPP telecommand and send its hexadecimal representation "
            "to a GNU Radio ZMQ PULL Message Source."
        )
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"GNU Radio ZMQ endpoint (default: {DEFAULT_ENDPOINT})",
    )
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
        "--connect-wait",
        type=float,
        default=0.1,
        help="seconds to allow the ZMQ connection to establish before sending",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def send_hex_payload(endpoint: str, payload: bytes, connect_wait: float) -> None:
    context = zmq.Context()
    txsock = context.socket(zmq.PUSH)
    txsock.setsockopt(zmq.LINGER, 0)

    try:
        txsock.connect(endpoint)
        if connect_wait > 0:
            time.sleep(connect_wait)

        pdu_bytes = pmt.serialize_str(pmt.intern(payload.hex()))
        print(f"[+] Sending hex payload via ZMQ to {endpoint}...")
        txsock.send(pdu_bytes, flags=zmq.NOBLOCK)
        print("[+] Telecommand queued successfully.")
    except zmq.Again as exc:
        raise RuntimeError("ZMQ send queue is not ready") from exc
    except zmq.ZMQError as exc:
        raise RuntimeError(f"ZMQ transport error: {exc}") from exc
    finally:
        txsock.close()
        context.term()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "gs-auth" and args.handshake == "finish" and args.challenge is None:
        parser.error("--challenge is required with --command gs-auth --handshake finish")
    if args.connect_wait < 0:
        parser.error("--connect-wait cannot be negative")

    payload = build_wire_payload(args)
    raw_spp = build_tc(APID_NAMES[args.command], payload, args.seq)

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
    print("[ZMQ string payload]")
    print(raw_spp.hex())

    if args.dry_run:
        return 0

    try:
        send_hex_payload(args.endpoint, raw_spp, args.connect_wait)
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
