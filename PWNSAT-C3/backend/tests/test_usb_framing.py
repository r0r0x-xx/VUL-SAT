"""Edge cases for usb_tc_send.iter_usb_sync_packets against the firmware's
asymmetric TM framing (obcUSBTransmitFrame: a single 0xAA sync byte, then the
raw SPP packet, no length prefix -- frame length is recovered from the SPP
header's own length field).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import settings  # noqa: E402

from spp_tools import build_tm  # noqa: E402
from usb_tc_send import iter_usb_sync_packets  # noqa: E402


def tm_frame(apid: int, payload: bytes, seq: int = 1) -> bytes:
    """Mirrors src/usbCDC.cpp:obcUSBTransmitFrame -- single 0xAA sync byte
    then the raw SPP packet, nothing else."""
    return b"\xAA" + build_tm(apid, payload, seq)


def test_single_packet():
    frame = tm_frame(0x01, b"ACK\x00")
    packets, trailing = iter_usb_sync_packets(frame)
    assert len(packets) == 1
    assert trailing == b""
    assert packets[0] == frame[1:]


def test_two_packets_back_to_back():
    stream = tm_frame(0x01, b"ACK\x00") + tm_frame(0x0C, b"\x01\x02\x03")
    packets, trailing = iter_usb_sync_packets(stream)
    assert len(packets) == 2
    assert trailing == b""


def test_trailing_partial_packet_is_not_consumed():
    complete = tm_frame(0x01, b"ACK\x00")
    partial = tm_frame(0x0C, b"\x01\x02\x03")[:-2]  # cut short
    stream = complete + partial
    packets, trailing = iter_usb_sync_packets(stream)
    assert len(packets) == 1
    assert trailing == partial


def test_split_across_two_reads_reassembles_via_trailing_buffer():
    frame = tm_frame(0x0E, b"\x01" * 20)
    midpoint = len(frame) // 2
    first_chunk, second_chunk = frame[:midpoint], frame[midpoint:]

    packets, trailing = iter_usb_sync_packets(first_chunk)
    assert packets == []
    # caller re-feeds trailing + next chunk, as serial_link.py's reader loop does
    packets, trailing = iter_usb_sync_packets(trailing + second_chunk)
    assert len(packets) == 1
    assert trailing == b""


def test_embedded_0xAA_byte_in_payload_is_not_mistaken_for_a_new_sync():
    # A payload containing a literal 0xAA byte is legal; the deframer must
    # trust the SPP header's own length field, not scan for the next 0xAA.
    payload = bytes([0x10, 0xAA, 0x20, 0xAA, 0x30])
    frame = tm_frame(0x09, payload)
    packets, trailing = iter_usb_sync_packets(frame)
    assert len(packets) == 1
    assert trailing == b""
    assert packets[0] == frame[1:]
