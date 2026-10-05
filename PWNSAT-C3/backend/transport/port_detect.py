"""Auto-detects which USB serial port is the FlatSat's binary CCSDS link.

Why this exists: the firmware exposes two USB CDC interfaces (see
New-firmware/usbCDC.cpp) -- a plain-text debug console (`Serial`) and the
binary telecommand/telemetry link (`USBRadioLink`) -- but both share the
exact same USB serial-number string ("fsat", set from
`TinyUSBDevice.setSerialDescriptor()` in `obcSetupUSB()`, called from both
cores with an identical literal). Since the OS has no per-interface
identifier to key off, which one enumerates as e.g. `/dev/tty.usbmodemfsat1`
vs `...fsat3` is decided by enumeration order at (re)connect time -- not
stable. Confirmed in practice: after a single physical USB
disconnect/reconnect, the two swapped, which is exactly the failure mode
this module exists to make irrelevant.

Detection strategy: actively probe each candidate port by sending a PING
telecommand and checking for an 0xAA-framed response. This is used instead
of passively listening for periodic telemetry because the binary link's
own beacon cadence is slow (14-30s, see worker.cpp's t_radio_* intervals) --
racing that passively would make every cold start slow and occasionally
flaky. The debug-only console has no command parser at all (`Serial` is
output-only in this firmware), so writing a telecommand frame into it can
never produce a false positive -- it simply goes nowhere.
"""
from __future__ import annotations

import logging
from typing import List, Optional

import serial
import serial.tools.list_ports

log = logging.getLogger("pwnsat_c3.port_detect")

PROBE_BAUD = 921600
PROBE_TIMEOUT_S = 1.5
PROBE_READ_BYTES = 64
BINARY_SYNC_BYTE = 0xAA


def candidate_ports() -> List[str]:
    """Every serial port currently enumerated by the OS -- not filtered to
    "looks like a FlatSat" by name/VID/PID on purpose: the whole point is
    not to assume anything about naming, since that's exactly what broke.
    Harmless to probe an unrelated serial device -- worst case it doesn't
    respond to our PING frame and gets skipped."""
    return sorted(p.device for p in serial.tools.list_ports.comports())


def _build_ping_probe_frame() -> Optional[bytes]:
    # Imported lazily, not at module load: pwnsat_tools/ is only on
    # sys.path once backend.settings has run (see serial_link.py's same
    # pattern), and this module may be imported before that in some
    # contexts. Falling back to None means _probe_port() below still works
    # via a bare read (can't distinguish "silent right now" from "wrong
    # port" quite as fast, but never wrong).
    try:
        from spp_tools import build_tc
        from usb_tc_send import frame_usb
    except ImportError:
        return None
    return frame_usb(build_tc(0x01, b"", 1))  # APID 0x01 = PING, no payload


def _probe_port(port_name: str, probe_frame: Optional[bytes]) -> bool:
    try:
        with serial.Serial(port_name, PROBE_BAUD, timeout=PROBE_TIMEOUT_S) as ser:
            if probe_frame is not None:
                ser.write(probe_frame)
                ser.flush()
            sample = ser.read(PROBE_READ_BYTES)
    except serial.SerialException as exc:
        log.debug("port_detect: could not open %s: %s", port_name, exc)
        return False
    return bool(sample) and sample[0] == BINARY_SYNC_BYTE


def find_binary_link_port(candidates: Optional[List[str]] = None) -> Optional[str]:
    """Returns the serial port that answered a PING probe with an
    0xAA-framed response, or None if nothing did (FlatSat not connected,
    not powered, or genuinely not responding). Tries every currently
    enumerated serial port -- not just ones that look like a FlatSat by
    name, per the module docstring."""
    if candidates is None:
        candidates = candidate_ports()

    probe_frame = _build_ping_probe_frame()
    for port in candidates:
        if _probe_port(port, probe_frame):
            log.info("port_detect: %s answered a PING probe -- using it as the binary CCSDS link", port)
            return port
        log.debug("port_detect: %s did not answer the PING probe (not the binary link)", port)
    return None
