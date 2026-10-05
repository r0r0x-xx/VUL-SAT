"""Firmware emulado del FlatSat: dispatch por APID sobre estado en memoria.
Sin I/O — testeable aislado. Reusa el toolkit vendored para los bytes SPP.

Los layouts de payload de cada TM están copiados byte-exacto de
`PWNSAT-C3/backend/tm_decoder.py` (NO se re-derivan acá, ver
docs/vulsat-telemetry-gps-dualpty-spec.md).
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import vendored  # noqa: F401  (pone pwnsat_tools en sys.path)
from spp_tools import build_tm, decode_packet
from pwnsat_crypto import encrypt_payload, decrypt_payload

APID_PING = 0x01
APID_FIRMWARE = 0x03
APID_SET_THRUSTER = 0x04
APID_SET_BEACON = 0x05
APID_BROADCAST = 0x06
APID_SENSOR = 0x08
APID_ERROR = 0x09
APID_AES = 0x0A
APID_STATUS = 0x0C
APID_MISSION_MODE = 0x0D
APID_NAV = 0x0E
APID_PAYLOAD_STATUS = 0x0F
APID_GS_STATUS = 0x13

IMPLEMENTED_APIDS = {
    APID_PING, APID_FIRMWARE, APID_SET_THRUSTER, APID_SET_BEACON,
    APID_BROADCAST, APID_SENSOR, APID_AES, APID_STATUS, APID_MISSION_MODE,
    APID_NAV, APID_PAYLOAD_STATUS, APID_GS_STATUS,
}
MAX_APID = 0x7FF

# --- constantes del "firmware" (ver spec, mission.h / worker.cpp) ---------

SPACECRAFT_ID = 1

# status_flags (mission.h): BME_OK | ACC_OK | GPS_UART_OK | GPS_FIX |
# SECURE_LINK | GPS_NMEA_ACTIVE (sin PAYLOAD_ARMED ni USB_DEBUG).
STATUS_FLAGS_BASE = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x80  # 0x9F
STATUS_FLAG_SECURE_LINK = 0x10

# gps_status_flags: UART_OK | CONNECTED | NMEA_ACTIVE | FIX_VALID | TIME_VALID
GPS_STATUS_FLAGS = 0x01 | 0x02 | 0x04 | 0x08 | 0x10  # 0x1F
GPS_SATS = 9

# gs_status_flags (parciales usados acá): GPS_VALID | GATE_OPEN | WITHIN_RANGE
GS_STATUS_GPS_VALID = 0x02
GS_STATUS_GATE_OPEN = 0x20
GS_STATUS_WITHIN_RANGE = 0x04

# firmware 1.3.0 (orden de empaquetado: patch, minor, major)
FW_MAJOR = 1
FW_MINOR = 3
FW_PATCH = 0

MODE_NOMINAL = 0
MODE_NAMES = {MODE_NOMINAL: "NOMINAL"}
MODE_NUMS = {name: num for num, name in MODE_NAMES.items()}

# --- modelo GPS (sat sobre Cartago, CR -> órbita; GS fija en México) ------

CARTAGO_LAT_DEG = 9.8638
CARTAGO_LON_DEG = -83.9195
ORBIT_ALT_CM = 500_000 * 100  # ~500 km LEO

GS_LAT_DEG = 19.4326   # Ciudad de México
GS_LON_DEG = -99.1332
GS_LAT_E7 = int(round(GS_LAT_DEG * 1e7))
GS_LON_E7 = int(round(GS_LON_DEG * 1e7))
GS_RADIUS_M = 60_000  # 60 km

# Velocidad de avance de la traza terrestre (longitud) y periodo/amplitud
# de la oscilación de latitud (modelo simplificado, no orbital real).
GROUND_TRACK_LON_RATE_DEG_S = 0.05
GROUND_TRACK_LAT_AMPLITUDE_DEG = 20.0
GROUND_TRACK_LAT_PERIOD_S = 180.0
GROUND_TRACK_LAT_LIMIT_DEG = 85.0

EARTH_RADIUS_M = 6_371_000.0


def _wrap180(deg: float) -> float:
    """Envuelve un ángulo en grados al rango [-180, 180)."""
    return ((deg + 180.0) % 360.0) - 180.0


def haversine_m(lat1_deg: float, lon1_deg: float, lat2_deg: float, lon2_deg: float) -> float:
    """Distancia entre dos puntos (lat/lon en grados) sobre la Tierra, en metros."""
    phi1, phi2 = math.radians(lat1_deg), math.radians(lat2_deg)
    dphi = math.radians(lat2_deg - lat1_deg)
    dlmb = math.radians(lon2_deg - lon1_deg)
    a = (math.sin(dphi / 2.0) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_M * c


@dataclass
class SatelliteState:
    orbit_angle: float = 0.0
    uptime_s: int = 0
    mode: str = "NOMINAL"
    mode_num: int = MODE_NOMINAL
    thruster: list = field(default_factory=lambda: [0, 0])
    beacon_rate_s: int = 18
    aes_enabled: bool = True
    link_up: bool = True
    crashed: bool = False
    seen_apids: set = field(default_factory=set)
    last_event: str = ""

    # --- GPS: posición actual del satélite (grados*1e7 / cm) ---
    lat_e7: int = int(round(CARTAGO_LAT_DEG * 1e7))
    lon_e7: int = int(round(CARTAGO_LON_DEG * 1e7))
    alt_cm: int = ORBIT_ALT_CM
    gps_t: float = 0.0  # tiempo acumulado para el modelo de traza terrestre


class SatelliteCore:
    def __init__(self, state: SatelliteState | None = None) -> None:
        self.state = state or SatelliteState()

    def _logical_payload(self, pkt) -> bytes:
        """Devuelve el payload en claro (descifra si aes_enabled, con fallback a claro)."""
        if self.state.aes_enabled and pkt.data:
            try:
                return decrypt_payload(pkt.data)
            except Exception:
                return pkt.data  # no descifrable -> tratar como claro
        return pkt.data

    def handle_tc(self, raw_spp: bytes) -> list:
        try:
            pkt = decode_packet(raw_spp)
        except Exception:
            return []  # basura / truncado -> silencio
        apid = pkt.apid
        self.state.seen_apids.add(apid)

        # Si está crasheado, no responder a nada hasta reboot
        if self.state.crashed:
            return []

        if apid not in IMPLEMENTED_APIDS:
            # APID válido pero no implementado -> ERROR TM (recon cat. 2)
            msg = f"APID 0x{apid:02X} not implemented".encode("ascii")
            return [self._reply(APID_ERROR, msg, pkt.sequence_count)]

        if apid == APID_PING:
            return [self._reply(APID_PING, bytes([SPACECRAFT_ID]) + b"PONG",
                                pkt.sequence_count)]

        if apid == APID_FIRMWARE:
            return [self.build_firmware_tm(pkt.sequence_count)]

        if apid == APID_AES:
            logical = self._logical_payload(pkt)
            self.state.aes_enabled = bool(logical and logical[0])
            self.state.last_event = f"AES {'ON' if self.state.aes_enabled else 'OFF'}"
            return [self._reply(APID_AES,
                                bytes([SPACECRAFT_ID, 1 if self.state.aes_enabled else 0]),
                                pkt.sequence_count)]

        if apid == APID_SET_THRUSTER:
            p = self._logical_payload(pkt)
            if len(p) >= 2:
                tid = p[0] & 0x01
                self.state.thruster[tid] = p[1] & 0xFF
                self.state.last_event = f"SET_THRUSTER t{tid}={p[1] & 0xFF} (sin auth!)"
            return [self.build_status_tm(pkt.sequence_count)]

        if apid == APID_SET_BEACON:
            p = self._logical_payload(pkt)
            if p:
                self.state.beacon_rate_s = max(1, p[0] & 0xFF)
                self.state.last_event = f"SET_BEACON_RATE={self.state.beacon_rate_s}s"
            return [self._reply(APID_SET_BEACON, bytes([self.state.beacon_rate_s]),
                                pkt.sequence_count)]

        if apid == APID_BROADCAST:
            p = self._logical_payload(pkt)
            if len(p) == 0:
                # Underflow en la longitud -> memcpy sin chequear (PoC 02)
                self.state.crashed = True
                self.state.link_up = False
                self.state.last_event = "CRASH: BROADCAST_MSG underflow"
                return []
            self.state.last_event = f"BROADCAST_MSG ({len(p)}B)"
            return [self._reply(APID_BROADCAST, b"\x01", pkt.sequence_count)]

        if apid == APID_STATUS:
            return [self.build_status_tm(pkt.sequence_count)]

        if apid == APID_NAV:
            return [self.build_nav_tm(pkt.sequence_count)]

        if apid == APID_SENSOR:
            return [self.build_sensor_tm(pkt.sequence_count)]

        if apid == APID_MISSION_MODE:
            p = self._logical_payload(pkt)
            if p:
                num = p[0] & 0xFF
                self.state.mode_num = num
                self.state.mode = MODE_NAMES.get(num, f"MODE_{num}")
                self.state.last_event = f"MISSION_MODE={self.state.mode}"
            return [self.build_mission_mode_tm(pkt.sequence_count)]

        if apid == APID_PAYLOAD_STATUS:
            return [self.build_payload_status_tm(pkt.sequence_count)]

        if apid == APID_GS_STATUS:
            return [self.build_gs_status_tm(pkt.sequence_count)]

        return []  # APID implementado pero sin acción asociada

    def _reply(self, apid: int, payload: bytes, seq: int) -> bytes:
        """Construye un TM, cifrándolo si aes_enabled está activo."""
        data = encrypt_payload(payload) if self.state.aes_enabled else payload
        return build_tm(apid, data, seq)

    # --- helpers de estado ------------------------------------------------

    def _status_flags(self) -> int:
        flags = STATUS_FLAGS_BASE
        if not self.state.aes_enabled:
            flags &= ~STATUS_FLAG_SECURE_LINK
        return flags & 0xFF

    def _gps_position_deg(self) -> tuple:
        """Posición GPS actual del satélite (lat, lon) en grados."""
        return self.state.lat_e7 / 1e7, self.state.lon_e7 / 1e7

    def _gs_distance_m(self) -> float:
        sat_lat, sat_lon = self._gps_position_deg()
        return haversine_m(sat_lat, sat_lon, GS_LAT_DEG, GS_LON_DEG)

    # --- payloads por APID (ver spec para el layout byte-exacto) ----------

    def _status_payload(self) -> bytes:
        """STATUS (APID 0x0C) -- decode_mission_status."""
        now = datetime.now(timezone.utc)
        head = bytes([
            SPACECRAFT_ID,
            self.state.mode_num & 0xFF,
            self._status_flags(),
            GPS_STATUS_FLAGS,
            self.state.beacon_rate_s & 0xFF,
            self.state.thruster[0] & 0xFF,
            self.state.thruster[1] & 0xFF,
            GPS_SATS,
        ])
        tail = struct.pack(
            "<HHIBBBBBHBBB",
            0,  # payload_fwd_count
            0,  # last_payload_freq
            self.state.uptime_s & 0xFFFFFFFF,
            now.hour, now.minute, now.second, now.day, now.month, now.year,
            FW_PATCH, FW_MINOR, FW_MAJOR,
        )
        return head + tail

    def _nav_payload(self) -> bytes:
        """NAV (APID 0x0E) -- decode_nav."""
        now = datetime.now(timezone.utc)
        head = bytes([SPACECRAFT_ID, GPS_STATUS_FLAGS, GPS_SATS])
        pos = struct.pack("<iii", self.state.lat_e7, self.state.lon_e7, self.state.alt_cm)
        utc1 = bytes([now.hour, now.minute, now.second, now.day, now.month])
        utc2 = struct.pack("<H", now.year)
        # Acelerómetro: ~1g en Z, ruido leve en X/Y, temp fija 25.00°C. Todo
        # *100 como int16 (entran holgadamente en -32768..32767).
        accel = struct.pack("<hhhh", 5, -3, 981, 2500)
        return head + pos + utc1 + utc2 + accel

    def _sensor_payload(self) -> bytes:
        """SENSOR (APID 0x08 SEND_TM) -- decode_sensor_tm.

        Valores *100 como int16 (ver spec: bme_pressure/altitude van
        escalados, no son hPa/metros reales -- de lo contrario desbordan
        int16).
        """
        accel_x_cent = 5
        accel_y_cent = -3
        accel_z_cent = 981       # 9.81 m/s^2 (~1g)
        accel_temp_cent = 2500   # 25.00 °C
        bme_temp_cent = 2250     # 22.50 °C
        bme_pressure_cent = 8700     # "87.00" (escalado, no hPa real)
        bme_altitude_cent = 30000    # "300.00" (escalado)
        bme_humidity_cent = 5500     # 55.00 %
        body = struct.pack(
            "<8h", accel_x_cent, accel_y_cent, accel_z_cent, accel_temp_cent,
            bme_temp_cent, bme_pressure_cent, bme_altitude_cent, bme_humidity_cent,
        )
        tail = bytes([self.state.thruster[0] & 0xFF, self.state.thruster[1] & 0xFF])
        return bytes([SPACECRAFT_ID]) + body + tail

    def _mission_mode_payload(self) -> bytes:
        """MISSION_MODE (APID 0x0D) -- decode_mission_mode."""
        return bytes([SPACECRAFT_ID, self.state.mode_num & 0xFF, 0, self._status_flags()])

    def _payload_status_payload(self) -> bytes:
        """PAYLOAD_STATUS (APID 0x0F) -- decode_payload_status."""
        head = bytes([
            SPACECRAFT_ID,
            self.state.mode_num & 0xFF,
            0,  # payload_armed
            1 if self.state.aes_enabled else 0,  # secure_link_enabled
        ])
        tail = struct.pack("<HHBB", 0, 0, 0, 0)
        return head + tail

    def _gs_status_payload(self) -> bytes:
        """GS_STATUS (APID 0x13) -- decode_gs_status."""
        distance_m = self._gs_distance_m()
        within_range = distance_m < GS_RADIUS_M
        distance_u16 = min(int(distance_m), 0xFFFF)
        gs_flags = GS_STATUS_GPS_VALID | GS_STATUS_GATE_OPEN
        if within_range:
            gs_flags |= GS_STATUS_WITHIN_RANGE
        head = bytes([SPACECRAFT_ID, gs_flags & 0xFF, GPS_STATUS_FLAGS])
        tail = struct.pack(
            "<HHIHiiH",
            distance_u16,
            0,  # session_remaining_s
            0,  # challenge
            0,  # handshake_remaining_s
            GS_LAT_E7,
            GS_LON_E7,
            GS_RADIUS_M,
        )
        return head + tail

    # --- builders públicos (usados por handle_tc y TelemetryScheduler) ----

    def build_status_tm(self, seq: int) -> bytes:
        return self._reply(APID_STATUS, self._status_payload(), seq)

    def build_nav_tm(self, seq: int) -> bytes:
        return self._reply(APID_NAV, self._nav_payload(), seq)

    def build_sensor_tm(self, seq: int) -> bytes:
        return self._reply(APID_SENSOR, self._sensor_payload(), seq)

    def build_mission_mode_tm(self, seq: int) -> bytes:
        return self._reply(APID_MISSION_MODE, self._mission_mode_payload(), seq)

    def build_payload_status_tm(self, seq: int) -> bytes:
        return self._reply(APID_PAYLOAD_STATUS, self._payload_status_payload(), seq)

    def build_gs_status_tm(self, seq: int) -> bytes:
        return self._reply(APID_GS_STATUS, self._gs_status_payload(), seq)

    def build_firmware_tm(self, seq: int) -> bytes:
        return self._reply(APID_FIRMWARE, bytes([SPACECRAFT_ID, FW_PATCH, FW_MINOR, FW_MAJOR]), seq)

    def reboot(self) -> None:
        """Reinicia el firmware desde un crash."""
        self.state.crashed = False
        self.state.link_up = True
        self.state.uptime_s = 0
        self.state.last_event = "REBOOT"

    def is_alive(self) -> bool:
        """Retorna True si el satélite está operacional."""
        return not self.state.crashed and self.state.link_up

    def tick(self, dt: float) -> None:
        """Avanza uptime_s, orbit_angle (mód 360) y la posición GPS si is_alive()."""
        if not self.is_alive():
            return
        self.state.uptime_s += int(dt)
        self.state.orbit_angle = (self.state.orbit_angle + dt * 0.5) % 360.0

        # Traza terrestre simplificada: la longitud avanza linealmente
        # (envolviendo en ±180) y la latitud oscila senoidalmente alrededor
        # de Cartago, acotada a ±85°.
        self.state.gps_t += dt
        lon_deg = _wrap180(CARTAGO_LON_DEG + GROUND_TRACK_LON_RATE_DEG_S * self.state.gps_t)
        lat_osc = GROUND_TRACK_LAT_AMPLITUDE_DEG * math.sin(
            2.0 * math.pi * self.state.gps_t / GROUND_TRACK_LAT_PERIOD_S
        )
        lat_deg = max(-GROUND_TRACK_LAT_LIMIT_DEG,
                      min(GROUND_TRACK_LAT_LIMIT_DEG, CARTAGO_LAT_DEG + lat_osc))
        self.state.lat_e7 = int(round(lat_deg * 1e7))
        self.state.lon_e7 = int(round(lon_deg * 1e7))
        self.state.alt_cm = ORBIT_ALT_CM
