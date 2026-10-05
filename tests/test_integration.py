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
                   c3_port_file=str(tmp_path / ".c3_port"),
                   sat_port_file=str(tmp_path / ".sat_port"))
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


def test_attacker_port_tc_reaches_core_and_c3_port_gets_the_tm(tmp_path):
    """Doble PTY: un TC inyectado por el puerto ATACANTE cambia el estado
    del core, y la TM resultante se entrega también por el puerto C3 --
    así C3 ve el efecto del ataque sin perder su conexión."""
    core = SatelliteCore(SatelliteState(aes_enabled=True))
    link = PtyLink(on_tc=lambda tc: [link.send_tm(f) for f in core.handle_tc(tc)],
                   c3_port_file=str(tmp_path / ".c3_port"),
                   sat_port_file=str(tmp_path / ".sat_port"))
    c3_fd = os.open(link.c3_slave_name, os.O_RDWR | os.O_NOCTTY)
    sat_fd = os.open(link.sat_slave_name, os.O_RDWR | os.O_NOCTTY)
    try:
        tc = build_tc(APID_SET_THRUSTER, encrypt_payload(bytes([1, 200])), 1)
        os.write(sat_fd, frame_usb(tc))
        link.pump_once(timeout=1.0)

        assert core.state.thruster[1] == 200        # el ataque cambió el estado
        # la TM resultante llega por el puerto C3 (que ni participó del TC)
        resp = os.read(c3_fd, 256)
        assert resp[0] == 0xAA
    finally:
        os.close(c3_fd)
        os.close(sat_fd)
        link.close()
