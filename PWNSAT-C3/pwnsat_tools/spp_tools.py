"""Small Space Packet Protocol helpers for the Pwnsat booklet exercises."""

from __future__ import annotations

import struct
from dataclasses import dataclass


APIDS = {
    0x01: "PING",
    0x02: "RESETC",
    0x03: "SEND_FW",
    0x04: "SET_THRUSTER",
    0x05: "SET_BEACON_RATE",
    0x06: "BROADCAST_MSG",
    0x07: "FLASH",
    0x08: "SEND_TM",
    0x09: "ERROR",
    0x0A: "AES_CONFIG",
    0x0B: "FLASH_READ",
    0x0C: "STATUS",
    0x0D: "MISSION_MODE",
    0x0E: "NAV",
    0x0F: "PAYLOAD_STATUS",
    0x10: "DEBUG_CONFIG",
    0x11: "GS_MODE",
    0x12: "GS_ACCESS",
    0x13: "GS_STATUS",
    0x7FF: "IDLE",
}


SEQ_FLAGS = {
    0b00: "Continuation",
    0b01: "First segment",
    0b10: "Last segment",
    0b11: "Unsegmented",
}

# Mirrors New-firmware/spp.h's SPP_SECONDARY_HEADER_LEN: a 4-byte plain
# counter, opt-in per packet via the SecHdr flag. No crypto semantics here
# (no IV, no freshness validation) -- see build_tc/build_tm below.
SEC_HEADER_LEN = 4


@dataclass
class DecodedPacket:
    raw: bytes
    version: int
    packet_type: int
    secondary_header: int
    apid: int
    sequence_flags: int
    sequence_count: int
    length_field: int
    data_field_size: int
    secondary_header_bytes: bytes
    data: bytes
    trailing: bytes

    @property
    def packet_type_name(self) -> str:
        return "TM" if self.packet_type == 0 else "TC"

    @property
    def apid_name(self) -> str:
        return APIDS.get(self.apid, "UNKNOWN")


def build_primary_header(
    apid: int,
    packet_type: int = 1,
    sequence_count: int = 0,
    data_len: int = 0,
    sequence_flags: int = 0b11,
    secondary_header: int = 0,
) -> bytes:
    """Build a CCSDS-style SPP primary header.

    `data_len` is the CCSDS length field value, not the raw payload size.
    A value of 0 means the packet declares one byte of data.
    """
    packet_id = 0
    packet_id |= (0 & 0x7) << 13
    packet_id |= (packet_type & 0x1) << 12
    packet_id |= (secondary_header & 0x1) << 11
    packet_id |= apid & 0x7FF

    sequence = 0
    sequence |= (sequence_flags & 0x3) << 14
    sequence |= sequence_count & 0x3FFF

    return struct.pack(">HHH", packet_id, sequence, data_len & 0xFFFF)


def build_tc(
    apid: int,
    payload: bytes = b"",
    sequence_count: int = 1,
    secondary_header_bytes: bytes = b"",
) -> bytes:
    """Build a basic telecommand packet.

    CCSDS stores data field size minus one. Empty payloads are represented by a
    zero-length field in many exercise builders, but strict CCSDS packets have at
    least one data byte. This helper mirrors the lab style and uses max(len-1, 0).

    `secondary_header_bytes`, when non-empty, is prepended to `payload` and the
    SecHdr flag is set -- mirrors New-firmware's opt-in secured format
    (spp_tc_build_packet_secured in spp.cpp). Leaving it empty (the default)
    reproduces the exact plain packet every other command in this repo still
    builds; nothing about the default call signature changed.
    """
    full_data = secondary_header_bytes + payload
    length_field = max(len(full_data) - 1, 0)
    return build_primary_header(
        apid=apid,
        packet_type=1,
        sequence_count=sequence_count,
        data_len=length_field,
        secondary_header=1 if secondary_header_bytes else 0,
    ) + full_data

def build_tm(
    apid: int,
    payload: bytes = b"",
    sequence_count: int = 1,
    secondary_header_bytes: bytes = b"",
) -> bytes:
    """Build a basic telemetry packet.

    CCSDS stores data field size minus one. Empty payloads are represented by a
    zero-length field in many exercise builders, but strict CCSDS packets have at
    least one data byte. This helper mirrors the lab style and uses max(len-1, 0).

    See build_tc() above for `secondary_header_bytes`.
    """
    full_data = secondary_header_bytes + payload
    length_field = max(len(full_data) - 1, 0)
    return build_primary_header(
        apid=apid,
        packet_type=0,
        sequence_count=sequence_count,
        data_len=length_field,
        secondary_header=1 if secondary_header_bytes else 0,
    ) + full_data

def decode_packet(raw: bytes) -> DecodedPacket:
    if len(raw) < 6:
        raise ValueError("SPP packet must contain at least a 6-byte primary header")

    packet_id, sequence, length_field = struct.unpack_from(">HHH", raw, 0)
    version          = (packet_id >> 13) & 0x7
    packet_type      = (packet_id >> 12) & 0x1
    secondary_header = (packet_id >> 11) & 0x1
    apid             = packet_id & 0x7FF
    sequence_flags   = (sequence >> 14) & 0x3
    sequence_count   = sequence & 0x3FFF
    data_field_size  = length_field + 1
    expected_total   = 6 + data_field_size
    full_data        = raw[6:expected_total]
    trailing = raw[expected_total:]

    # When the SecHdr flag is set, the first SEC_HEADER_LEN bytes of the data
    # field are the secondary header, not payload -- split them out here so
    # `.data` always means "the real payload" for every existing consumer
    # (telemetry_bus.py, tm_decoder.py) without either having to know this
    # format exists. Falls back to treating everything as payload if the
    # packet claims a secondary header but is too short to actually hold one
    # (truncated/malformed input) rather than raising.
    if secondary_header and len(full_data) >= SEC_HEADER_LEN:
        secondary_header_bytes = full_data[:SEC_HEADER_LEN]
        data = full_data[SEC_HEADER_LEN:]
    else:
        secondary_header_bytes = b""
        data = full_data

    return DecodedPacket(
        raw=raw,
        version=version,
        packet_type=packet_type,
        secondary_header=secondary_header,
        apid=apid,
        sequence_flags=sequence_flags,
        sequence_count=sequence_count,
        length_field=length_field,
        data_field_size=data_field_size,
        secondary_header_bytes=secondary_header_bytes,
        data=data,
        trailing=trailing,
    )


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02X}" for byte in chunk).ljust(width * 3)
        ascii_bytes = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")
    return "\n".join(lines)


def print_packet(raw: bytes) -> DecodedPacket:
    packet = decode_packet(raw)
    print("=========== Space Packet ===========")
    print(f"Version:              {packet.version}")
    print(f"Type:                 {packet.packet_type} ({packet.packet_type_name})")
    print(f"Secondary Header:     {packet.secondary_header}")
    print(f"APID:                 0x{packet.apid:03X} ({packet.apid_name})")
    print(
        f"Sequence Flags:       0b{packet.sequence_flags:02b} "
        f"({SEQ_FLAGS.get(packet.sequence_flags, 'Unknown')})"
    )
    print(f"Sequence Count:       {packet.sequence_count}")
    print(f"Length Field:         {packet.length_field}")
    print(f"Data Field Size:      {packet.data_field_size}")
    print(f"Captured Bytes:       {len(raw)}")
    print()
    print("[HEADER]")
    print(hexdump(raw[:6]))
    if packet.secondary_header_bytes:
        print()
        print("[SECONDARY HEADER]")
        print(hexdump(packet.secondary_header_bytes))
    if packet.data:
        print()
        print("[DATA]")
        print(hexdump(packet.data))
    if packet.trailing:
        print()
        print("[TRAILING]")
        print(hexdump(packet.trailing))
    return packet
