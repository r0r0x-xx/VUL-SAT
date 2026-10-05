import os
import vulsat_sim.vendored  # noqa: F401
from spp_tools import build_tc, decode_packet
from pwnsat_crypto import encrypt_payload, decrypt_payload
from usb_tc_send import frame_usb
from vulsat_sim.satellite_core import SatelliteCore, SatelliteState, APID_SET_THRUSTER
from vulsat_sim.pty_link import PtyLink


def test_thruster_injection_end_to_end(tmp_path):
    core = SatelliteCore(SatelliteState(aes_enabled=True))
    link = PtyLink(on_tc=lambda tc: [link.send_tm(f) for f in core.handle_tc(tc)],
                   port_file=str(tmp_path / ".sat_port"))
    fd = os.open(link.slave_name, os.O_RDWR | os.O_NOCTTY)
    try:
        # SET_THRUSTER t0=255, payload cifrado (como el PoC 03 --encrypt on)
        tc = build_tc(APID_SET_THRUSTER, encrypt_payload(bytes([0, 255])), 1)
        os.write(fd, frame_usb(tc))
        link.pump_once(timeout=1.0)
        assert core.state.thruster[0] == 255           # efecto del PoC 03
        resp = os.read(fd, 256)
        assert resp[0] == 0xAA                          # respondió STATUS framed
    finally:
        os.close(fd)
        link.close()
