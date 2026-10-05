"""Structured telemetry decoders.

Byte layouts here are the exact inverse of the real firmware's TM builders in
`src/worker.cpp`, verified directly against that source. Every payload's
leading byte is `spacecraft_id`; everything after is per-APID.

Status-flag bitmasks are copied 1:1 from `src/mission.h` -- do not re-derive
them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

# --- status-flag bit constants (src/mission.h) ---

MISSION_FLAG_BME_OK = 0x01
MISSION_FLAG_ACC_OK = 0x02
MISSION_FLAG_GPS_UART_OK = 0x04
MISSION_FLAG_GPS_FIX = 0x08
MISSION_FLAG_SECURE_LINK = 0x10
MISSION_FLAG_PAYLOAD_ARMED = 0x20
MISSION_FLAG_USB_DEBUG = 0x40
MISSION_FLAG_GPS_NMEA_ACTIVE = 0x80

GPS_STATUS_UART_OK = 0x01
GPS_STATUS_CONNECTED = 0x02
GPS_STATUS_NMEA_ACTIVE = 0x04
GPS_STATUS_FIX_VALID = 0x08
GPS_STATUS_TIME_VALID = 0x10

GS_STATUS_MODE_ENABLED = 0x01
GS_STATUS_GPS_VALID = 0x02
GS_STATUS_WITHIN_RANGE = 0x04
GS_STATUS_AUTH_ACTIVE = 0x08
GS_STATUS_HANDSHAKE_PENDING = 0x10
GS_STATUS_GATE_OPEN = 0x20

GS_AUTH_STATE_NAMES = {
    0x00: "challenge-issued",
    0x01: "accepted",
    0x02: "rejected",
    0x03: "challenge-missing",
}


def mission_flags(byte: int) -> dict:
    return {
        "bme_ok": bool(byte & MISSION_FLAG_BME_OK),
        "acc_ok": bool(byte & MISSION_FLAG_ACC_OK),
        "gps_uart_ok": bool(byte & MISSION_FLAG_GPS_UART_OK),
        "gps_fix": bool(byte & MISSION_FLAG_GPS_FIX),
        "secure_link": bool(byte & MISSION_FLAG_SECURE_LINK),
        "payload_armed": bool(byte & MISSION_FLAG_PAYLOAD_ARMED),
        "usb_debug": bool(byte & MISSION_FLAG_USB_DEBUG),
        "gps_nmea_active": bool(byte & MISSION_FLAG_GPS_NMEA_ACTIVE),
    }


def gps_flags(byte: int) -> dict:
    return {
        "uart_ok": bool(byte & GPS_STATUS_UART_OK),
        "connected": bool(byte & GPS_STATUS_CONNECTED),
        "nmea_active": bool(byte & GPS_STATUS_NMEA_ACTIVE),
        "fix_valid": bool(byte & GPS_STATUS_FIX_VALID),
        "time_valid": bool(byte & GPS_STATUS_TIME_VALID),
    }


def gs_flags(byte: int) -> dict:
    return {
        "mode_enabled": bool(byte & GS_STATUS_MODE_ENABLED),
        "gps_valid": bool(byte & GS_STATUS_GPS_VALID),
        "within_range": bool(byte & GS_STATUS_WITHIN_RANGE),
        "auth_active": bool(byte & GS_STATUS_AUTH_ACTIVE),
        "handshake_pending": bool(byte & GS_STATUS_HANDSHAKE_PENDING),
        "gate_open": bool(byte & GS_STATUS_GATE_OPEN),
    }


def crc8(data: bytes) -> int:
    """CRC-8, poly 0x07, init 0x00 -- matches src/worker.cpp:crc8_compute."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


# --- per-APID dataclasses -------------------------------------------------


@dataclass
class MissionStatusTM:
    spacecraft_id: int
    mission_mode: int
    status_flags: int
    gps_status_flags: int
    beacon_interval_s: int
    thruster0: int
    thruster1: int
    gps_sats: int
    payload_fwd_count: int
    last_payload_freq: int
    uptime_s: int
    utc_hour: int
    utc_minute: int
    utc_second: int
    utc_day: int
    utc_month: int
    utc_year: int
    fw_patch: int
    fw_minor: int
    fw_major: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["status_flags_decoded"] = mission_flags(self.status_flags)
        d["gps_status_flags_decoded"] = gps_flags(self.gps_status_flags)
        d["fw_version"] = f"{self.fw_major}.{self.fw_minor}.{self.fw_patch}"
        return d


@dataclass
class MissionModeTM:
    spacecraft_id: int
    mission_mode: int
    payload_armed: int
    status_flags: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["status_flags_decoded"] = mission_flags(self.status_flags)
        return d


@dataclass
class PayloadStatusTM:
    spacecraft_id: int
    mission_mode: int
    payload_armed: int
    secure_link_enabled: int
    last_payload_freq: int
    payload_fwd_count: int
    last_payload_len: int

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class NavTM:
    spacecraft_id: int
    gps_status_flags: int
    gps_sats: int
    lat_e7: int
    lon_e7: int
    alt_cm: int
    utc_hour: int
    utc_minute: int
    utc_second: int
    utc_day: int
    utc_month: int
    utc_year: int
    accel_x: float
    accel_y: float
    accel_z: float
    accel_temp: float

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["gps_status_flags_decoded"] = gps_flags(self.gps_status_flags)
        d["latitude_deg"] = self.lat_e7 / 1e7
        d["longitude_deg"] = self.lon_e7 / 1e7
        d["altitude_m"] = self.alt_cm / 100.0
        return d


@dataclass
class PwncubeNavTM:
    """PWNCUBE's own TM_NAV (backed by its GPS_OVERRIDE debug hook) -- NOT
    FlatSat's NAV (that's APID 0x0E, decoded by NavTM/decode_nav above).
    PWNCUBE reused APID 0x0B for this instead, which collides with
    FlatSat's FLASH_READ in the shared APID_TM_DECODERS table below --
    decode() special-cases 0x0B by platform to pick this decoder instead
    of decode_flash_read() when platform=="pwncube"."""
    spacecraft_id: int
    override_active: int
    satellites: int
    lat_e7: int
    lon_e7: int
    alt_cm: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["latitude_deg"] = self.lat_e7 / 1e7
        d["longitude_deg"] = self.lon_e7 / 1e7
        d["altitude_m"] = self.alt_cm / 100.0
        return d


@dataclass
class GsModeTM:
    spacecraft_id: int
    requested_mode: int
    gs_mode_enabled: int
    gs_status_flags: int
    gps_status_flags: int
    session_remaining_s: int
    handshake_remaining_s: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["gs_status_flags_decoded"] = gs_flags(self.gs_status_flags)
        d["gps_status_flags_decoded"] = gps_flags(self.gps_status_flags)
        return d


@dataclass
class GsAccessTM:
    spacecraft_id: int
    phase: int
    auth_state: int
    gs_status_flags: int
    gps_status_flags: int
    challenge: int
    session_remaining_s: int
    handshake_remaining_s: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["auth_state_name"] = GS_AUTH_STATE_NAMES.get(self.auth_state, f"0x{self.auth_state:02X}")
        d["gs_status_flags_decoded"] = gs_flags(self.gs_status_flags)
        d["gps_status_flags_decoded"] = gps_flags(self.gps_status_flags)
        return d


@dataclass
class GsStatusTM:
    spacecraft_id: int
    gs_status_flags: int
    gps_status_flags: int
    distance_m: int
    session_remaining_s: int
    challenge: int
    handshake_remaining_s: int
    gs_lat_e7: int
    gs_lon_e7: int
    gs_radius_m: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["gs_status_flags_decoded"] = gs_flags(self.gs_status_flags)
        d["gps_status_flags_decoded"] = gps_flags(self.gps_status_flags)
        d["gs_latitude_deg"] = self.gs_lat_e7 / 1e7
        d["gs_longitude_deg"] = self.gs_lon_e7 / 1e7
        return d


@dataclass
class FirmwareVersionTM:
    spacecraft_id: int
    patch: int
    minor: int
    major: int

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["version"] = f"{self.major}.{self.minor}.{self.patch}"
        return d


@dataclass
class AesConfigTM:
    spacecraft_id: int
    secure_link_enabled: int

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DebugConfigTM:
    spacecraft_id: int
    usb_debug_enabled: int
    secure_link_enabled: int

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SensorTM:
    spacecraft_id: int
    accel_x: float
    accel_y: float
    accel_z: float
    accel_temp_c: float
    bme_temp_c: float
    bme_pressure_hpa: float
    bme_altitude_m: float
    bme_humidity_pct: float
    thruster0_power: int
    thruster1_power: int

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PingAckTM:
    spacecraft_id: int
    text: str
    # Populated only when the reply used the opt-in CCSDS secondary-header
    # format (New-firmware spp_tm_build_packet_secured) -- a plain counter,
    # no crypto/security meaning attached yet. None for a normal PING ACK.
    secondary_header_counter: Optional[int] = None

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ErrorTM:
    message: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class FlashChunkTM:
    spacecraft_id: int
    index: int
    offset: int
    remaining: int
    chunk: bytes
    checksum: int
    checksum_ok: bool

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["chunk"] = self.chunk.hex()
        return d


@dataclass
class FlashReadTM:
    spacecraft_id: int
    offset: int
    copy_len: int
    chunk: bytes
    checksum: int
    checksum_ok: bool

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["chunk"] = self.chunk.hex()
        d["chunk_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in self.chunk)
        return d


@dataclass
class BroadcastEchoTM:
    message: bytes

    def as_dict(self) -> dict:
        return {
            "message_hex": self.message.hex(),
            "message_text": self.message.decode("ascii", errors="replace"),
        }


# --- decoders --------------------------------------------------------------


def decode_mission_status(data: bytes) -> MissionStatusTM:
    (spacecraft_id, mode, flags, gps_flags_byte, beacon_s, t0, t1, sats) = data[0:8]
    (
        payload_fwd_count,
        last_payload_freq,
        uptime_s,
        utc_hour,
        utc_minute,
        utc_second,
        utc_day,
        utc_month,
        utc_year,
        fw_patch,
        fw_minor,
        fw_major,
    ) = struct.unpack_from("<HHIBBBBBHBBB", data, 8)
    return MissionStatusTM(
        spacecraft_id, mode, flags, gps_flags_byte, beacon_s, t0, t1, sats,
        payload_fwd_count, last_payload_freq, uptime_s, utc_hour, utc_minute,
        utc_second, utc_day, utc_month, utc_year, fw_patch, fw_minor, fw_major,
    )


def decode_mission_mode(data: bytes) -> MissionModeTM:
    spacecraft_id, mode, payload_armed, flags = data[0:4]
    return MissionModeTM(spacecraft_id, mode, payload_armed, flags)


def decode_payload_status(data: bytes) -> PayloadStatusTM:
    spacecraft_id, mode, payload_armed, secure_link_enabled = data[0:4]
    last_payload_freq, payload_fwd_count, last_payload_len, _pad = struct.unpack_from(
        "<HHBB", data, 4
    )
    return PayloadStatusTM(
        spacecraft_id, mode, payload_armed, secure_link_enabled,
        last_payload_freq, payload_fwd_count, last_payload_len,
    )


def decode_nav(data: bytes) -> NavTM:
    spacecraft_id, gps_flags_byte, sats = data[0:3]
    lat_e7, lon_e7, alt_cm = struct.unpack_from("<iii", data, 3)
    utc_hour, utc_minute, utc_second, utc_day, utc_month = data[15:20]
    (utc_year,) = struct.unpack_from("<H", data, 20)
    accel_x, accel_y, accel_z, accel_temp = struct.unpack_from("<hhhh", data, 22)
    return NavTM(
        spacecraft_id, gps_flags_byte, sats, lat_e7, lon_e7, alt_cm,
        utc_hour, utc_minute, utc_second, utc_day, utc_month, utc_year,
        accel_x / 100.0, accel_y / 100.0, accel_z / 100.0, accel_temp / 100.0,
    )


def decode_pwncube_nav(data: bytes) -> PwncubeNavTM:
    """Inverse of command_service.c's telemetry_spp_transmit_nav(): 15
    bytes -- spacecraft_id(1) status(1) satellites(1) latE7(i32 LE)
    lonE7(i32 LE) altCm(i32 LE). Confirmed against real hardware."""
    spacecraft_id, status, satellites = data[0:3]
    lat_e7, lon_e7, alt_cm = struct.unpack_from("<iii", data, 3)
    return PwncubeNavTM(spacecraft_id, status, satellites, lat_e7, lon_e7, alt_cm)


def decode_gs_mode(data: bytes) -> GsModeTM:
    spacecraft_id, requested_mode, gs_mode_enabled, gs_flags_byte, gps_flags_byte = data[0:5]
    session_remaining_s, handshake_remaining_s = struct.unpack_from("<HH", data, 5)
    return GsModeTM(
        spacecraft_id, requested_mode, gs_mode_enabled, gs_flags_byte,
        gps_flags_byte, session_remaining_s, handshake_remaining_s,
    )


def decode_gs_access(data: bytes) -> GsAccessTM:
    spacecraft_id, phase, auth_state, gs_flags_byte, gps_flags_byte = data[0:5]
    challenge, session_remaining_s, handshake_remaining_s = struct.unpack_from(
        "<IHH", data, 5
    )
    return GsAccessTM(
        spacecraft_id, phase, auth_state, gs_flags_byte, gps_flags_byte,
        challenge, session_remaining_s, handshake_remaining_s,
    )


def decode_gs_status(data: bytes) -> GsStatusTM:
    spacecraft_id, gs_flags_byte, gps_flags_byte = data[0:3]
    distance_m, session_remaining_s, challenge, handshake_remaining_s, gs_lat_e7, gs_lon_e7, gs_radius_m = (
        struct.unpack_from("<HHIHiiH", data, 3)
    )
    return GsStatusTM(
        spacecraft_id, gs_flags_byte, gps_flags_byte, distance_m,
        session_remaining_s, challenge, handshake_remaining_s, gs_lat_e7,
        gs_lon_e7, gs_radius_m,
    )


def decode_firmware_version(data: bytes) -> FirmwareVersionTM:
    spacecraft_id, patch, minor, major = data[0:4]
    return FirmwareVersionTM(spacecraft_id, patch, minor, major)


def decode_aes_config(data: bytes) -> AesConfigTM:
    spacecraft_id, secure_link_enabled = data[0:2]
    return AesConfigTM(spacecraft_id, secure_link_enabled)


def decode_debug_config(data: bytes) -> DebugConfigTM:
    spacecraft_id, usb_debug_enabled, secure_link_enabled = data[0:3]
    return DebugConfigTM(spacecraft_id, usb_debug_enabled, secure_link_enabled)


def decode_sensor_tm(data: bytes) -> SensorTM:
    """APID 0x08 (SEND_TM) -- inverse of telemetrySPPPackFrame/
    telemetrySPPPackFillFloatToBuffer in worker.cpp: spacecraft_id, then 8
    signed int16 LE fixed-point values (scale 100.0) for accel x/y/z/temp
    and BME temp/pressure/altitude/humidity, then 2 raw thruster bytes, then
    a trailing NUL the firmware pads the buffer with (not part of the data)."""
    spacecraft_id = data[0]
    x, y, z, t, tm, p, alt, hum = struct.unpack_from("<8h", data, 1)
    thruster0_power, thruster1_power = data[17], data[18]
    return SensorTM(
        spacecraft_id,
        x / 100.0, y / 100.0, z / 100.0, t / 100.0,
        tm / 100.0, p / 100.0, alt / 100.0, hum / 100.0,
        thruster0_power, thruster1_power,
    )


def decode_ping_ack(data: bytes, secondary_header_bytes: bytes = b"") -> PingAckTM:
    spacecraft_id = data[0]
    text = data[1:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    counter = int.from_bytes(secondary_header_bytes, "big") if secondary_header_bytes else None
    return PingAckTM(spacecraft_id, text, counter)


def decode_error(data: bytes) -> ErrorTM:
    message = data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return ErrorTM(message)


def decode_flash_chunk(data: bytes) -> FlashChunkTM:
    spacecraft_id = data[0]
    index, offset, remaining = struct.unpack_from("<HHH", data, 1)
    chunk = data[7:-1]
    checksum = data[-1]
    return FlashChunkTM(
        spacecraft_id, index, offset, remaining, chunk, checksum,
        checksum_ok=(crc8(chunk) == checksum),
    )


def decode_flash_read(data: bytes) -> FlashReadTM:
    spacecraft_id = data[0]
    (offset,) = struct.unpack_from("<H", data, 1)
    copy_len = data[3]
    chunk = data[4:4 + copy_len]
    checksum = data[4 + copy_len]
    return FlashReadTM(
        spacecraft_id, offset, copy_len, chunk, checksum,
        checksum_ok=(crc8(chunk) == checksum),
    )


def decode_broadcast_echo(data: bytes) -> BroadcastEchoTM:
    return BroadcastEchoTM(data)


# APID -> decoder function. Keys match spp_tools.APIDS / usb_tc_send.APID_NAMES.
APID_TM_DECODERS: Dict[int, Callable[[bytes], object]] = {
    0x01: decode_ping_ack,
    0x08: decode_sensor_tm,
    0x03: decode_firmware_version,
    0x06: decode_broadcast_echo,
    0x07: decode_flash_chunk,
    0x09: decode_error,
    0x0A: decode_aes_config,
    0x0B: decode_flash_read,
    0x0C: decode_mission_status,
    0x0D: decode_mission_mode,
    0x0E: decode_nav,
    0x0F: decode_payload_status,
    0x10: decode_debug_config,
    0x11: decode_gs_mode,
    0x12: decode_gs_access,
    0x13: decode_gs_status,
}

APID_TM_NAMES = {
    0x01: "PING",
    0x03: "SEND_FW",
    0x08: "SEND_TM",
    0x06: "BROADCAST_MSG",
    0x07: "FLASH",
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


def decode(
    apid: int, plaintext_data: bytes, secondary_header_bytes: bytes = b"",
    platform: str = "flatsat",
) -> Optional[object]:
    """Decode an already-decrypted TM payload for the given APID. Returns
    None (caller falls back to raw hexdump) for APIDs with no structured
    decoder yet.

    `secondary_header_bytes` is only meaningful for PING (0x01) right now --
    the opt-in secured-format pilot, see decode_ping_ack(). Every other APID
    ignores it; passing it always is simpler than threading a special case
    through every decoder's call site.

    `platform` only matters for APID 0x0B, which means two different
    things depending on which craft sent it: FlatSat's FLASH_READ vs.
    PWNCUBE's own TM_NAV -- see PwncubeNavTM's docstring. Every other APID
    means the same thing on both platforms.
    """
    if apid == 0x0B and platform == "pwncube":
        return decode_pwncube_nav(plaintext_data)
    decoder = APID_TM_DECODERS.get(apid)
    if decoder is None:
        return None
    if apid == 0x01:
        return decode_ping_ack(plaintext_data, secondary_header_bytes)
    return decoder(plaintext_data)
