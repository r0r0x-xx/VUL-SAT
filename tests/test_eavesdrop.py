# tests/test_eavesdrop.py -- PoC 01 (eavesdropping): sólo la parte pura
# (deframe + decode), sin abrir ningún puerto real.
import vulsat_sim.vendored  # noqa: F401
from spp_tools import build_tc
from pwnsat_crypto import encrypt_payload
from usb_tc_send import iter_usb_sync_packets

from vulsat_sim.eavesdrop import describe_tm


def _bare_frame(raw_spp: bytes) -> bytes:
    """Framing desnudo satélite->tierra (0xAA + SPP), el que usa PtyLink.send_tm."""
    return b"\xAA" + raw_spp


def test_describe_tm_cleartext_payload():
    raw = build_tc(0x0C, b"\x01", 1)  # STATUS, payload crudo, no es un bloque AES
    line = describe_tm(raw, aes_enabled=True)
    assert "APID=0x00C" in line
    assert "STATUS" in line
    assert "payload" in line


def test_describe_tm_encrypted_payload_is_decrypted():
    plain = b"hola-mundo"
    raw = build_tc(0x04, encrypt_payload(plain), 1)  # SET_THRUSTER, cifrado
    line = describe_tm(raw, aes_enabled=True)
    assert plain.hex() in line
    assert "AES->plano" in line


def test_describe_tm_invalid_spp_does_not_raise():
    line = describe_tm(b"\x00\x01", aes_enabled=True)
    assert "inválido" in line


def test_iter_usb_sync_packets_matches_bare_tm_framing():
    raw = build_tc(0x0E, b"\x02", 1)
    stream = b"\xDE\xAD" + _bare_frame(raw)  # basura + una TM bien enmarcada
    packets, rest = iter_usb_sync_packets(stream)
    assert len(packets) == 1
    assert rest == b""
    line = describe_tm(packets[0])
    assert "NAV" in line
