"""PWNCUBE transport: talks to the board over its USB gadget link.

Unlike FlatSat, PWNCUBE has no dedicated CDC-ACM command port -- its gadget
interface is a vendor-specific (class 0xff) bulk pair, and the RV1106's two
cores never expose a raw binary SPP link to the outside: TCs only ever go
out via the RT-Thread/RISC-V core's own `radio_test tcsend <apid_hex>
<payload_hex>` CLI, reached over rpmsg from inside the Cortex-A7 Linux side
(see the PWNCUBE firmware repo for the full rpmsg/USB-gadget picture).

So this transport still speaks "raw SPP bytes in" like every other one (the
`Transport` ABC contract), but internally it decodes those bytes with
pwnsat_tools/spp_tools.py (the same helper every attack script already uses
to build them) and re-encodes them as that CLI's text syntax, instead of
writing framed bytes straight to a wire like SerialTransport does.

The board's ttyGS0 boots into a menu (`pwnsat_console`), not a raw shell --
so connect() has to navigate into "3) Debug Shell" before any `radio_test`
command means anything. Since we don't know what state a freshly-plugged-in
board is already in (menu, mid-dashboard, already in a shell from a
previous connection), connect() sends the menu shortcut then verifies an
actual shell prompt responds via an echo marker, which works regardless of
the starting state.

Background telemetry reader: a second process reading the same tty
concurrently (`radio_test tlm &` left running, writing to the shared
console) corrupts console output, so instead of a foreground blocking read,
this transport starts `radio_test tlm` in the background on the BOARD with
its output redirected to a FILE, never the tty, so nothing interleaves with
send_tc()'s own shell commands. A persistent background thread here polls
that file with `cat` + a byte offset every ~2s and re-parses any new
`[TM] ...` blocks into raw SPP frames via `_emit()`, for the whole life of
the connection -- this is what gives PWNCUBE's dashboard the same
"telemetry just keeps flowing over USB, independent of whatever the RF
hardware is doing" property FlatSat's real serial CDC link has always had
for free (without this, panels that depend on live telemetry go stale
during an RF-only attack that needs the USB link otherwise idle). Uses its
own log filename so a standalone attack script's own telemetry monitor
never collides with it -- they only ever run at different times anyway,
since either one holding the USB interface means the other physically
cannot be connected too.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import usb.core
import usb.util

from .. import settings  # noqa: F401  (ensures pwnsat_tools/ is on sys.path)
from spp_tools import decode_packet

from .base import Transport

log = logging.getLogger("pwnsat_c3.pwncube_link")

# PWNCUBE's USB gadget descriptor (vendor-specific bulk pair, not CDC-ACM --
# see pwncube_console.py). Fixed by the firmware's gadget config, not
# something to auto-probe for.
VID, PID = 0x2207, 0x0011
EP_OUT, EP_IN = 0x01, 0x81
READ_CHUNK = 512

# pwnsat_console.c's menu: "3) Debug Shell". Sent blind on connect since we
# don't know the board's current menu state (see module docstring).
_MENU_KEY_DEBUG_SHELL = "3"
_SHELL_READY_MARKER = "PWNSAT_C3_SHELL_READY"

# Own log file, distinct from the standalone attack scripts' own telemetry
# monitor log (PWNCUBE's own repo) -- see module docstring's last paragraph.
_TLM_LOGFILE = "/tmp/pwncube_c3_tlm.log"
_TLM_POLL_INTERVAL_S = 2.0


class PwncubeTransport(Transport):
    def __init__(self) -> None:
        super().__init__()
        self._dev: Optional[usb.core.Device] = None
        self._write_lock = threading.Lock()
        self._connected = False
        self._tlm_stop = threading.Event()
        self._tlm_thread: Optional[threading.Thread] = None
        self._tlm_chars_seen = 0
        self._tlm_leftover = ""

    @property
    def description(self) -> str:
        return f"PWNCUBE USB ({VID:04x}:{PID:04x})"

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def supports_tx(self) -> bool:
        return True

    def connect(self) -> None:
        # Idempotent: app.py's _connect_with_retry watchdog now calls this
        # again any time t.connected is False, including after a mid-session
        # drop where send_tc() caught a USBError and set _connected=False
        # without ever tearing down self._dev/the tlm background thread.
        # Clean up any stale state first so re-claiming the interface below
        # doesn't collide with our own leftover handle.
        if self._dev is not None:
            self._stop_tlm_background()
            self._teardown_device()

        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is None:
            raise RuntimeError(
                f"PWNCUBE not found (VID:PID {VID:04x}:{PID:04x}) -- "
                "not connected, not booted, or still enumerating"
            )
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
        self._dev = dev

        try:
            self._ensure_shell()
        except Exception:
            self._teardown_device()
            raise

        self._connected = True
        self._start_tlm_background()
        log.info("connected: %s", self.description)

    def disconnect(self) -> None:
        self._connected = False
        self._stop_tlm_background()
        self._teardown_device()

    def send_tc(self, raw_spp: bytes) -> None:
        if not self._connected or self._dev is None:
            raise RuntimeError("pwncube transport is not connected")

        pkt = decode_packet(raw_spp)
        cmd = f"radio_test tcsend {pkt.apid:02X}"
        if pkt.data:
            cmd += " " + " ".join(f"{b:02X}" for b in pkt.data)

        try:
            response = self._run_shell_command(cmd, settle=0.6)
        except usb.core.USBError as exc:
            self._connected = False
            raise RuntimeError(f"pwncube USB write/read failed: {exc}") from exc

        if "OK" not in response:
            raise RuntimeError(f"pwncube tcsend for APID 0x{pkt.apid:02X} failed: {response!r}")

    # --- internals -----------------------------------------------------

    def _ensure_shell(self) -> None:
        """Gets a live `/bin/sh` prompt on ttyGS0 regardless of whatever menu
        state the console was already in (see module docstring)."""
        self._drain(300)
        self._write(_MENU_KEY_DEBUG_SHELL + "\n")
        time.sleep(0.5)
        self._drain(300)
        self._write(f"echo {_SHELL_READY_MARKER}\n")
        time.sleep(0.5)
        response = self._drain(800)
        if _SHELL_READY_MARKER not in response:
            raise RuntimeError(
                "could not reach a Debug Shell prompt on PWNCUBE's console "
                "(menu changed, or the board is stuck elsewhere)"
            )

    def _run_shell_command(self, cmd: str, settle: float = 0.5) -> str:
        # Holds _write_lock for the WHOLE write-sleep-drain sequence, not
        # just each individual _write()/_drain() call -- needed now that
        # the background tlm poller (_tlm_poll_once) also calls this method
        # from its own thread: without one lock spanning the full sequence,
        # a send_tc() from the request thread and a poll tick from the
        # background thread could interleave their writes/reads on the same
        # USB endpoints and corrupt both (one thread's `_write(cmd)` landing
        # before the other's matching `_drain()`).
        with self._write_lock:
            self._drain_unlocked(200)
            self._write_unlocked(cmd + "\n")
            time.sleep(settle)
            return self._drain_unlocked(600)

    # --- background telemetry (see module docstring's "Background
    # telemetry reader" paragraph) --------------------------------

    def _start_tlm_background(self) -> None:
        self._tlm_chars_seen = 0
        self._tlm_leftover = ""
        self._tlm_stop.clear()
        try:
            self._run_shell_command(f"rm -f {_TLM_LOGFILE}", settle=0.2)
            self._run_shell_command(f"radio_test tlm > {_TLM_LOGFILE} 2>&1 &", settle=0.3)
        except usb.core.USBError:
            log.warning("could not start background radio_test tlm -- "
                        "telemetry over USB will not flow, TX still works")
            return
        self._tlm_thread = threading.Thread(
            target=self._tlm_poll_loop, name="pwncube-tlm-poll", daemon=True,
        )
        self._tlm_thread.start()

    def _stop_tlm_background(self) -> None:
        self._tlm_stop.set()
        if self._tlm_thread is not None:
            self._tlm_thread.join(timeout=_TLM_POLL_INTERVAL_S + 1.0)
            self._tlm_thread = None
        if self._dev is not None:
            try:
                self._run_shell_command("pkill -f 'radio_test tlm'", settle=0.3)
            except usb.core.USBError:
                pass  # tearing down anyway

    def _tlm_poll_loop(self) -> None:
        while not self._tlm_stop.wait(_TLM_POLL_INTERVAL_S):
            if not self._connected:
                return
            try:
                self._tlm_poll_once()
            except usb.core.USBError as exc:
                log.warning("pwncube tlm poll USB error (will retry): %s", exc)
            except Exception:
                log.exception("pwncube tlm poll failed")

    def _tlm_poll_once(self) -> None:
        text = self._run_shell_command(f"cat {_TLM_LOGFILE}", settle=0.3)
        if len(text) <= self._tlm_chars_seen:
            return  # nothing new (board rebooted and log reset counts as "nothing new" too -- next poll catches up once it's grown again)
        new_text = text[self._tlm_chars_seen:]
        self._tlm_chars_seen = len(text)

        combined = self._tlm_leftover + new_text
        lines = combined.split("\n")
        self._tlm_leftover = lines[-1]  # may be a not-yet-complete trailing line
        complete_lines = lines[:-1]

        i = 0
        while i < len(complete_lines):
            line = complete_lines[i].strip()
            if line.startswith("[TM]") and i + 1 < len(complete_lines):
                hex_line = complete_lines[i + 1].strip().replace(" ", "")
                try:
                    raw = bytes.fromhex(hex_line)
                except ValueError:
                    raw = b""
                if raw:
                    self._emit(raw)
                i += 2
                continue
            i += 1

    def _write(self, text: str) -> None:
        """Locked convenience wrapper -- only used by _ensure_shell(),
        which runs during connect() before any other thread (send_tc()
        callers, the tlm poller) exists yet, so a lock per call vs. one
        spanning the whole method makes no observable difference there."""
        with self._write_lock:
            self._write_unlocked(text)

    def _drain(self, timeout_ms: int) -> str:
        with self._write_lock:
            return self._drain_unlocked(timeout_ms)

    def _write_unlocked(self, text: str) -> None:
        assert self._dev is not None
        self._dev.write(EP_OUT, text.encode())

    def _drain_unlocked(self, timeout_ms: int) -> str:
        assert self._dev is not None
        out = b""
        while True:
            try:
                out += bytes(self._dev.read(EP_IN, READ_CHUNK, timeout=timeout_ms))
            except usb.core.USBError:
                break
        return out.decode(errors="replace")

    def _teardown_device(self) -> None:
        if self._dev is None:
            return
        try:
            usb.util.release_interface(self._dev, 0)
        except usb.core.USBError:
            pass
        usb.util.dispose_resources(self._dev)
        self._dev = None
