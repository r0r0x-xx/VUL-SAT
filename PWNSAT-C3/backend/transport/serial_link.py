"""Real-hardware transport: talks to the FlatSat's USBRadioLink CDC port.

Reuses the framing helpers already written and verified against the firmware
in pwnsat_tools/usb_tc_send.py:

- `frame_usb`  -- ground -> satellite command framing (0xAA 0x55 <len> <SPP>)
- `iter_usb_sync_packets` -- satellite -> ground telemetry deframing (bare
  0xAA sync byte, frame length recovered from the SPP header's own length
  field, since the firmware's TX path does not send a length prefix)
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import serial

from .. import settings  # noqa: F401  (ensures pwnsat_tools/ is on sys.path)
from usb_tc_send import frame_usb, iter_usb_sync_packets

from .base import Transport

log = logging.getLogger("pwnsat_c3.serial_link")

# How often to retry reopening the port after it drops mid-session (e.g. the
# board rebooting from a RESETC command or a crash -- the USB CDC device
# disconnects and re-enumerates for a few seconds). Separate from the
# startup-time retry in app.py's _connect_with_retry(), which only covers
# "the port was never there yet"; this one covers "it was open, then died".
RECONNECT_INTERVAL_S = 2.0


class SerialTransport(Transport):
    def __init__(self, port: str, baud: int = settings.DEFAULT_BAUD) -> None:
        super().__init__()
        self._port_name = port
        self._baud = baud
        self._ser: Optional[serial.Serial] = None
        self._write_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._rx_buffer = bytearray()

    @property
    def description(self) -> str:
        return f"FlatSat USB ({self._port_name} @ {self._baud} baud)"

    @property
    def connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    def connect(self) -> None:
        self._ser = serial.Serial(self._port_name, self._baud, timeout=0.2)
        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._read_loop, name="serial-reader", daemon=True
        )
        self._reader_thread.start()
        log.info("connected: %s", self.description)

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None
        self._close_port()

    def send_tc(self, raw_spp: bytes) -> None:
        if not self.connected:
            raise RuntimeError("serial transport is not connected")
        frame = frame_usb(raw_spp)
        with self._write_lock:
            assert self._ser is not None
            self._ser.write(frame)
            self._ser.flush()

    def _close_port(self) -> None:
        if self._ser is not None:
            with self._write_lock:
                try:
                    self._ser.close()
                except serial.SerialException:
                    pass
            self._ser = None

    def _reopen_port(self) -> bool:
        try:
            new_ser = serial.Serial(self._port_name, self._baud, timeout=0.2)
        except serial.SerialException:
            return False
        with self._write_lock:
            self._ser = new_ser
        return True

    def _read_loop(self) -> None:
        was_connected = True
        while not self._stop_event.is_set():
            if self._ser is None or not self._ser.is_open:
                if was_connected:
                    log.warning(
                        "serial port %s dropped (board reset/disconnect?) -- "
                        "retrying every %.0fs until it comes back",
                        self._port_name, RECONNECT_INTERVAL_S,
                    )
                    was_connected = False
                if self._reopen_port():
                    # WARNING (not INFO) so this shows up under uvicorn's
                    # default log level without extra logging config -- the
                    # "dropped" message above is the same level for the same
                    # reason, they're meant to be read together at a glance.
                    log.warning("serial port %s reconnected", self._port_name)
                    was_connected = True
                    self._rx_buffer = bytearray()  # discard any partial frame from before the drop
                else:
                    self._stop_event.wait(RECONNECT_INTERVAL_S)
                continue

            try:
                with self._write_lock:
                    chunk = self._ser.read(settings.SERIAL_READ_CHUNK)
            except serial.SerialException:
                self._close_port()
                continue
            if not chunk:
                continue
            self._rx_buffer.extend(chunk)
            packets, trailing = iter_usb_sync_packets(bytes(self._rx_buffer))
            self._rx_buffer = bytearray(trailing)
            for raw_spp in packets:
                self._emit(raw_spp)
