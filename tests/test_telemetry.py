import vulsat_sim.vendored  # noqa: F401
from spp_tools import decode_packet
from vulsat_sim.satellite_core import SatelliteCore, SatelliteState, APID_STATUS, APID_NAV
from vulsat_sim.telemetry import TelemetryScheduler


def test_tick_advances_orbit_and_uptime():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    core.tick(10.0)
    assert core.state.uptime_s == 10
    assert core.state.orbit_angle > 0


def test_crashed_core_does_not_advance():
    core = SatelliteCore(SatelliteState(aes_enabled=False, crashed=True, link_up=False))
    core.tick(10.0)
    assert core.state.uptime_s == 0


def test_scheduler_emits_status_and_nav_when_due():
    core = SatelliteCore(SatelliteState(aes_enabled=False))
    sched = TelemetryScheduler(core, send=lambda b: None)
    frames = sched.due(elapsed=1000.0)  # bien pasado cualquier cadencia
    apids = {decode_packet(f).apid for f in frames}
    assert APID_STATUS in apids and APID_NAV in apids
