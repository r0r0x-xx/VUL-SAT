# tests/test_pty_link.py
import os
import vulsat_sim.vendored  # noqa: F401
from spp_tools import build_tc, decode_packet
from usb_tc_send import frame_usb
from vulsat_sim.pty_link import PtyLink, frame_tm, deframe_tcs


def test_frame_tm_prefixes_sync_byte():
    raw = build_tc(0x0C, b"\x01", 1)
    assert frame_tm(raw)[0] == 0xAA


def test_close_removes_stale_port_file(tmp_path):
    port_file = tmp_path / ".sat_port"
    link = PtyLink(on_tc=lambda tc: None, port_file=str(port_file))
    assert port_file.exists()
    link.close()
    assert not port_file.exists()
    link.close()  # idempotente: ya borrado, no debe explotar


def test_deframe_recovers_tc_after_garbage():
    raw = build_tc(0x01, b"", 1)
    stream = b"\xDE\xAD" + frame_usb(raw)       # basura + frame valido
    tcs, rest = deframe_tcs(stream)
    assert len(tcs) == 1
    assert decode_packet(tcs[0]).apid == 0x01


def test_pty_roundtrip_delivers_tc_and_tm(tmp_path):
    received = []
    link = PtyLink(on_tc=received.append, port_file=str(tmp_path / ".sat_port"))
    fd = None
    try:
        # un "ground station" abre el slave y manda un PING framed
        fd = os.open(link.slave_name, os.O_RDWR | os.O_NOCTTY)
        os.write(fd, frame_usb(build_tc(0x01, b"", 1)))
        link.pump_once(timeout=1.0)
        assert received and decode_packet(received[0]).apid == 0x01
        # el sat responde una TM y el ground la lee
        link.send_tm(build_tc(0x0C, b"\x02", 1))
        data = os.read(fd, 256)
        assert data[0] == 0xAA
    finally:
        if fd is not None:
            os.close(fd)
        link.close()
        # close() limpia .sat_port: no debe quedar apuntando a un PTY muerto.
        assert not os.path.exists(str(tmp_path / ".sat_port"))
