from vulsat_sim.satellite_core import SatelliteState
from vulsat_sim.tui import render, orbit_line


def test_render_shows_thruster_and_mode():
    s = SatelliteState(aes_enabled=False)
    s.thruster = [40, 0]
    s.last_event = "SET_THRUSTER t0=40"
    out = render(s)
    assert "THRUSTER" in out and "40" in out
    assert "NOMINAL" in out
    assert "SET_THRUSTER" in out


def test_render_shows_crash_state():
    s = SatelliteState(crashed=True, link_up=False)
    out = render(s)
    assert "CRASH" in out.upper()


def test_orbit_line_moves_marker():
    a = orbit_line(0.0, 40)
    b = orbit_line(180.0, 40)
    assert a.index("o") != b.index("o")
