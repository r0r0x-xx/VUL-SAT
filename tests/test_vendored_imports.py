import vulsat_sim.vendored  # noqa: F401  (side effect: sys.path)


def test_toolkit_imports_resolve():
    from spp_tools import build_tc, build_tm, decode_packet, SEC_HEADER_LEN
    from pwnsat_crypto import AES_KEY, encrypt_payload, decrypt_payload
    from usb_tc_send import frame_usb, iter_usb_sync_packets

    assert AES_KEY == b"PWNsatLabKey1234"
    assert SEC_HEADER_LEN == 4
    # round-trip mínimo del framing
    raw = build_tc(0x01, b"\x01", 1)
    assert frame_usb(raw).startswith(b"\xAA\x55")
