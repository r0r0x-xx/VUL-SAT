import vulsat_sim.vendored  # noqa: F401
from spp_tools import build_tc, decode_packet
from pwnsat_crypto import encrypt_payload, decrypt_payload
from vulsat_sim.satellite_core import (
    SatelliteCore, SatelliteState,
    APID_PING, APID_ERROR, APID_AES, APID_SET_THRUSTER, APID_SET_BEACON, APID_STATUS,
    APID_BROADCAST,
)


def test_ping_gets_a_response():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    out = core.handle_tc(build_tc(APID_PING, b"", 1))
    assert len(out) == 1
    assert decode_packet(out[0]).apid == APID_PING


def test_valid_but_unimplemented_apid_returns_error_tm():
    # 0x20 es un APID válido (<=0x7FF) que el firmware no implementa
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    out = core.handle_tc(build_tc(0x20, b"\x01", 1))
    assert len(out) == 1
    assert decode_packet(out[0]).apid == APID_ERROR


def test_malformed_input_is_silent():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    assert core.handle_tc(b"\x00\x01") == []  # SPP < 6 bytes


def test_seen_apids_tracked_for_tui():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.handle_tc(build_tc(APID_PING, b"", 1))
    assert APID_PING in core.state.seen_apids


def test_encrypted_ping_roundtrips_when_aes_on():
    core = SatelliteCore(SatelliteState(aes_enabled=True))
    tc = build_tc(APID_PING, encrypt_payload(b""), 1)
    out = core.handle_tc(tc)
    assert len(out) == 1
    pkt = decode_packet(out[0])
    assert pkt.apid == APID_PING
    # la respuesta viene cifrada -> se puede descifrar sin error
    assert decrypt_payload(pkt.data) == b"\x01"


def test_aes_toggle_off_then_plaintext_accepted():
    core = SatelliteCore(SatelliteState(aes_enabled=True))
    # apagar AES: payload 0x00 cifrado (porque aún está on)
    core.handle_tc(build_tc(APID_AES, encrypt_payload(b"\x00"), 1))
    assert core.state.aes_enabled is False
    # ahora un PING en claro debe responder en claro
    out = core.handle_tc(build_tc(APID_PING, b"", 2))
    assert decode_packet(out[0]).data == b"\x01"


def test_set_thruster_without_auth_changes_power():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.handle_tc(build_tc(APID_SET_THRUSTER, bytes([0, 255]), 1))
    assert core.state.thruster[0] == 255          # cambió sin auth (finding PoC 03)
    assert "THRUSTER" in core.state.last_event


def test_set_beacon_rate_changes_cadence():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.handle_tc(build_tc(APID_SET_BEACON, bytes([5]), 1))
    assert core.state.beacon_rate_s == 5


def test_broadcast_zero_payload_crashes_mission():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    out = core.handle_tc(build_tc(APID_BROADCAST, b"", 1))
    assert out == []                 # el firmware crasheado no responde
    assert core.state.crashed is True
    assert core.is_alive() is False


def test_broadcast_normal_payload_is_safe():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.handle_tc(build_tc(APID_BROADCAST, b"hola", 1))
    assert core.state.crashed is False


def test_reboot_recovers():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.handle_tc(build_tc(APID_BROADCAST, b"", 1))
    core.reboot()
    assert core.is_alive() is True
    assert core.state.uptime_s == 0
