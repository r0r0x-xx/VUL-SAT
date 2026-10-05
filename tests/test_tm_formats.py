# tests/test_tm_formats.py -- byte-exacto: cada builder de TM produce un
# payload en claro que PWNSAT-C3/backend/tm_decoder.decode() parsea sin
# error y con los campos esperados (Cartago, GS México, uptime, thrusters,
# flags, fw 1.3.0). No se re-deriva ningún layout acá -- el decoder
# vendored es la autoridad (ver docs/vulsat-telemetry-gps-dualpty-spec.md).
import sys
from pathlib import Path

import pytest

import vulsat_sim.vendored  # noqa: F401  (pone pwnsat_tools en sys.path)
from pwnsat_crypto import decrypt_payload
from spp_tools import decode_packet

_C3_ROOT = Path(__file__).resolve().parents[1] / "PWNSAT-C3"
if str(_C3_ROOT) not in sys.path:
    sys.path.insert(0, str(_C3_ROOT))

from backend import tm_decoder  # noqa: E402

from vulsat_sim.satellite_core import (  # noqa: E402
    SatelliteCore, SatelliteState,
    APID_STATUS, APID_NAV, APID_SENSOR, APID_MISSION_MODE,
    APID_PAYLOAD_STATUS, APID_GS_STATUS, APID_PING, APID_ERROR, APID_AES,
    APID_FIRMWARE,
    CARTAGO_LAT_DEG, CARTAGO_LON_DEG, GS_LAT_DEG, GS_LON_DEG,
)


def _plain(core: SatelliteCore, raw_tm: bytes) -> bytes:
    """Payload en claro de una TM, descifrando si aes_enabled."""
    pkt = decode_packet(raw_tm)
    if core.state.aes_enabled:
        return decrypt_payload(pkt.data)
    return pkt.data


@pytest.fixture(params=[True, False], ids=["aes_on", "aes_off"])
def core(request) -> SatelliteCore:
    return SatelliteCore(SatelliteState(aes_enabled=request.param, uptime_s=12345))


def test_status_tm_decodes_with_expected_fields(core):
    raw = core.build_status_tm(1)
    data = _plain(core, raw)
    status = tm_decoder.decode(APID_STATUS, data, platform="flatsat")
    status_d = status.as_dict()
    assert status.spacecraft_id == 1
    assert status.uptime_s == 12345
    assert status.thruster0 == 0 and status.thruster1 == 0
    assert status.gps_sats == 9
    assert status_d["fw_version"] == "1.3.0"
    flags = status_d["status_flags_decoded"]
    assert flags["bme_ok"] and flags["acc_ok"] and flags["gps_fix"]
    assert flags["secure_link"] == core.state.aes_enabled
    assert status_d["gps_status_flags_decoded"]["fix_valid"]


def test_status_tm_reflects_thruster_and_beacon_state(core):
    core.state.thruster = [40, 7]
    core.state.beacon_rate_s = 3
    raw = core.build_status_tm(1)
    status = tm_decoder.decode(APID_STATUS, _plain(core, raw), platform="flatsat")
    assert status.thruster0 == 40 and status.thruster1 == 7
    assert status.beacon_interval_s == 3


def test_nav_tm_decodes_cartago_position(core):
    raw = core.build_nav_tm(1)
    nav = tm_decoder.decode(APID_NAV, _plain(core, raw), platform="flatsat")
    nav_d = nav.as_dict()
    assert nav.spacecraft_id == 1
    assert nav_d["latitude_deg"] == pytest.approx(CARTAGO_LAT_DEG, abs=1e-4)
    assert nav_d["longitude_deg"] == pytest.approx(CARTAGO_LON_DEG, abs=1e-4)
    assert nav_d["altitude_m"] == pytest.approx(500_000.0, rel=0.01)
    assert nav.accel_z == pytest.approx(9.81, abs=0.01)
    assert nav_d["gps_status_flags_decoded"]["fix_valid"]


def test_nav_tm_tracks_ground_track_after_tick(core):
    core.tick(10.0)
    raw = core.build_nav_tm(1)
    nav = tm_decoder.decode(APID_NAV, _plain(core, raw), platform="flatsat")
    # tras avanzar, la longitud se movió respecto a Cartago (traza terrestre)
    assert nav.as_dict()["longitude_deg"] != pytest.approx(CARTAGO_LON_DEG, abs=1e-4)


def test_sensor_tm_decodes_without_int16_overflow(core):
    raw = core.build_sensor_tm(1)
    sensor = tm_decoder.decode(APID_SENSOR, _plain(core, raw), platform="flatsat")
    assert sensor.spacecraft_id == 1
    assert sensor.accel_z == pytest.approx(9.81, abs=0.01)
    assert sensor.bme_temp_c == pytest.approx(22.5, abs=0.01)
    assert sensor.thruster0_power == core.state.thruster[0]
    assert sensor.thruster1_power == core.state.thruster[1]


def test_mission_mode_tm_decodes(core):
    raw = core.build_mission_mode_tm(1)
    mode_tm = tm_decoder.decode(APID_MISSION_MODE, _plain(core, raw), platform="flatsat")
    assert mode_tm.spacecraft_id == 1
    assert mode_tm.mission_mode == 0  # NOMINAL
    assert mode_tm.payload_armed == 0


def test_payload_status_tm_decodes(core):
    raw = core.build_payload_status_tm(1)
    pstatus = tm_decoder.decode(APID_PAYLOAD_STATUS, _plain(core, raw), platform="flatsat")
    assert pstatus.spacecraft_id == 1
    assert pstatus.secure_link_enabled == (1 if core.state.aes_enabled else 0)


def test_gs_status_tm_decodes_mexico_city_and_distance(core):
    raw = core.build_gs_status_tm(1)
    gs = tm_decoder.decode(APID_GS_STATUS, _plain(core, raw), platform="flatsat")
    gs_d = gs.as_dict()
    assert gs.spacecraft_id == 1
    assert gs_d["gs_latitude_deg"] == pytest.approx(GS_LAT_DEG, abs=1e-4)
    assert gs_d["gs_longitude_deg"] == pytest.approx(GS_LON_DEG, abs=1e-4)
    assert gs.gs_radius_m == 60_000
    # Cartago -> México son miles de km: fuera de rango y distancia > 0
    assert gs.distance_m > 60_000
    assert gs_d["gs_status_flags_decoded"]["gps_valid"]
    assert gs_d["gs_status_flags_decoded"]["gate_open"]
    assert not gs_d["gs_status_flags_decoded"]["within_range"]


def test_firmware_tm_decodes_as_1_3_0(core):
    raw = core.build_firmware_tm(1)
    fw = tm_decoder.decode(0x03, _plain(core, raw), platform="flatsat")
    assert fw.spacecraft_id == 1
    assert fw.as_dict()["version"] == "1.3.0"


def test_ping_ack_decodes_as_pong(core):
    from spp_tools import build_tc
    tc = build_tc(APID_PING, b"", 1)
    out = core.handle_tc(tc)
    assert len(out) == 1
    ping = tm_decoder.decode(APID_PING, _plain(core, out[0]), platform="flatsat")
    assert ping.spacecraft_id == 1
    assert ping.text == "PONG"


def test_error_tm_is_ascii_and_encrypted_when_aes_on(core):
    from spp_tools import build_tc
    tc = build_tc(0x20, b"\x01", 1)  # APID válido, no implementado
    out = core.handle_tc(tc)
    assert len(out) == 1
    err = tm_decoder.decode(APID_ERROR, _plain(core, out[0]), platform="flatsat")
    assert "not implemented" in err.message


def test_aes_config_tm_decodes_with_spacecraft_id(core):
    from spp_tools import build_tc
    from pwnsat_crypto import encrypt_payload
    payload = bytes([1]) if not core.state.aes_enabled else encrypt_payload(bytes([1]))
    tc = build_tc(APID_AES, payload, 1)
    out = core.handle_tc(tc)
    aes_tm = tm_decoder.decode(APID_AES, _plain(core, out[0]), platform="flatsat")
    assert aes_tm.spacecraft_id == 1
    assert aes_tm.secure_link_enabled == 1
