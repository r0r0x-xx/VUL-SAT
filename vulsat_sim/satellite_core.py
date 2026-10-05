"""Firmware emulado del FlatSat: dispatch por APID sobre estado en memoria.
Sin I/O — testeable aislado. Reusa el toolkit vendored para los bytes SPP.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import vendored  # noqa: F401  (pone pwnsat_tools en sys.path)
from spp_tools import build_tm, decode_packet
from pwnsat_crypto import encrypt_payload, decrypt_payload

APID_PING = 0x01
APID_SET_THRUSTER = 0x04
APID_SET_BEACON = 0x05
APID_BROADCAST = 0x06
APID_ERROR = 0x09
APID_AES = 0x0A
APID_STATUS = 0x0C
APID_NAV = 0x0E

IMPLEMENTED_APIDS = {
    APID_PING, APID_SET_THRUSTER, APID_SET_BEACON,
    APID_BROADCAST, APID_AES, APID_STATUS, APID_NAV,
}
MAX_APID = 0x7FF


@dataclass
class SatelliteState:
    orbit_angle: float = 0.0
    uptime_s: int = 0
    mode: str = "NOMINAL"
    thruster: list = field(default_factory=lambda: [0, 0])
    beacon_rate_s: int = 18
    aes_enabled: bool = True
    link_up: bool = True
    crashed: bool = False
    seen_apids: set = field(default_factory=set)
    last_event: str = ""


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
            return [build_tm(APID_ERROR, bytes([apid & 0xFF]), pkt.sequence_count)]

        if apid == APID_PING:
            return [self._reply(APID_PING, b"\x01", pkt.sequence_count)]

        if apid == APID_AES:
            logical = self._logical_payload(pkt)
            self.state.aes_enabled = bool(logical and logical[0])
            self.state.last_event = f"AES {'ON' if self.state.aes_enabled else 'OFF'}"
            return [self._reply(APID_AES, bytes([1 if self.state.aes_enabled else 0]),
                                pkt.sequence_count)]

        if apid == APID_SET_THRUSTER:
            p = self._logical_payload(pkt)
            if len(p) >= 2:
                tid = p[0] & 0x01
                self.state.thruster[tid] = p[1] & 0xFF
                self.state.last_event = f"SET_THRUSTER t{tid}={p[1] & 0xFF} (sin auth!)"
            return [self._reply(APID_STATUS, self._status_payload(), pkt.sequence_count)]

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

        return []  # APID implementado pero sin acción asociada

    def _reply(self, apid: int, payload: bytes, seq: int) -> bytes:
        """Construye un TM, cifrándolo si aes_enabled está activo."""
        data = encrypt_payload(payload) if self.state.aes_enabled else payload
        return build_tm(apid, data, seq)

    def _status_payload(self) -> bytes:
        """Layout del payload STATUS TM."""
        return bytes([
            self.state.thruster[0] & 0xFF,
            self.state.thruster[1] & 0xFF,
            self.state.beacon_rate_s & 0xFF,
            1 if self.state.aes_enabled else 0,
        ]) + (self.state.uptime_s & 0xFFFFFFFF).to_bytes(4, "big")

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
        """Avanza uptime_s y orbit_angle (mód 360) si is_alive()."""
        if not self.is_alive():
            return
        self.state.uptime_s += int(dt)
        self.state.orbit_angle = (self.state.orbit_angle + dt * 0.5) % 360.0

    def build_status_tm(self, seq: int) -> bytes:
        """Construye un TM STATUS (APID 0x0C) con payload _status_payload."""
        return self._reply(APID_STATUS, self._status_payload(), seq)

    def build_nav_tm(self, seq: int) -> bytes:
        """Construye un TM NAV (APID 0x0E) con orbit_angle*100 como uint16 BE."""
        ang = int(self.state.orbit_angle * 100) & 0xFFFF
        return self._reply(APID_NAV, ang.to_bytes(2, "big"), seq)
