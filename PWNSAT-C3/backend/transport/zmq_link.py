"""Real radio transport (RX): subscribes to the GNU Radio downlink receiver's
ZMQ PUB socket (see gradio/pwnsat_lora_rx.py + gradio/pwnsat_rx_bridge.py,
default tcp://127.0.0.1:5005, works with either an RTL-SDR or a HackRF via
GNU Radio's native Soapy blocks). Each `sock.recv()` there is already one
complete raw SPP packet -- LoRa's own packet framing does the deframing GNU
Radio's side needs, no byte-stream reassembly like the USB serial path
requires.

TX (sending commands/attacks over the uplink) is not implemented yet: no GNU
Radio TX flowgraph exists in this repo. `send_tc` raises a clear error rather
than silently doing nothing.

IMPORTANT: `gradio/pwnsat_rx_bridge.py` runs under a *different* Python than
this backend -- it needs `gnuradio`/`gnuradio.soapy`/`gnuradio.lora_sdr`
importable (e.g. a Homebrew or system Python with GNU Radio installed, see
INSTALL.md), while this backend runs in its own .venv. They are two separate
processes talking only over the ZMQ socket; this transport only needs
`pyzmq`, already a backend dependency.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import zmq

from .. import settings

from .base import Transport

log = logging.getLogger("pwnsat_c3.zmq_link")

RECV_TIMEOUT_MS = 500


class ZmqTransport(Transport):
    def __init__(self, address: str = "tcp://127.0.0.1:5005") -> None:
        super().__init__()
        self._address = address
        self._ctx: Optional[zmq.Context] = None
        self._sock: Optional[zmq.Socket] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._socket_open = False
        # A ZMQ SUB socket's connect() never fails even if nothing is
        # publishing on the other end (async by design, no handshake) -- so
        # "the socket is open" does not mean "a GNU Radio bridge is actually
        # running and sending packets". Track the last time a packet
        # actually arrived and use that for `connected` instead, so the
        # frontend's per-source indicator doesn't show "connected" with no
        # RTL-SDR/HackRF plugged in and no bridge running.
        self._last_recv_at: Optional[float] = None

    @property
    def description(self) -> str:
        return f"radio (RX only) via {self._address}"

    @property
    def connected(self) -> bool:
        if not self._socket_open or self._last_recv_at is None:
            return False
        # Same threshold the watchdog uses for the aggregate link state
        # ("connected" vs "stale"), so this per-source indicator means the
        # same thing when someone reads it next to the other one.
        return (time.monotonic() - self._last_recv_at) < settings.STALE_AFTER_S

    @property
    def supports_tx(self) -> bool:
        return False

    def connect(self) -> None:
        self._ctx = zmq.Context()
        self._sock = self._ctx.socket(zmq.SUB)
        self._sock.setsockopt(zmq.SUBSCRIBE, b"")
        self._sock.setsockopt(zmq.RCVTIMEO, RECV_TIMEOUT_MS)
        self._sock.connect(self._address)
        self._socket_open = True
        self._last_recv_at = None

        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._read_loop, name="zmq-reader", daemon=True
        )
        self._reader_thread.start()
        log.info("socket open (not necessarily receiving yet): %s", self.description)

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None
        if self._sock is not None:
            self._sock.close(0)
            self._sock = None
        if self._ctx is not None:
            self._ctx.term()
            self._ctx = None
        self._socket_open = False
        self._last_recv_at = None

    def send_tc(self, raw_spp: bytes) -> None:
        raise RuntimeError(
            "radio TX is not implemented yet -- no GNU Radio uplink "
            "flowgraph exists in this repo. Use the serial or cube "
            "transport to send commands; this transport is RX-only."
        )

    def _read_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                raw_spp = self._sock.recv()
            except zmq.Again:
                continue
            except zmq.ZMQError:
                if self._stop_event.is_set():
                    return
                log.exception("zmq recv failed, stopping reader thread")
                return
            self._last_recv_at = time.monotonic()
            self._emit(raw_spp)
