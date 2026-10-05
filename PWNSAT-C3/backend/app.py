"""FastAPI app: REST command/attack endpoints + websocket telemetry push.

Normal operation: point PWNSAT_C3_SERIAL_PORT at the FlatSat's USB CDC port.
The app also always tries to open the radio (ZMQ) source in parallel -- that
connect is cheap and harmless even with no RTL-SDR/GNU Radio bridge running
(a ZMQ SUB socket just sits there with nothing arriving). Whichever sources
actually came up are exposed to the operator as a runtime switch (POST
/api/transport) instead of being picked once at process start -- an operator
without an RTL-SDR just never sees a working "radio" option and stays on USB.

    PWNSAT_C3_SERIAL_PORT=/dev/tty.usbmodemXXXX \
        uvicorn backend.app:app --app-dir .

    PWNSAT_C3_SERIAL_PORT=/dev/tty.usbmodemXXXX PWNSAT_C3_ZMQ_ADDRESS=tcp://127.0.0.1:5005 \
        uvicorn backend.app:app --app-dir .

Commands/attacks always transmit over USB serial -- whichever source the
operator is *viewing* is independent of which one telecommands go out on,
because the radio side is receive-only today (no GNU Radio TX flowgraph
exists yet; see transport/zmq_link.py).

See ../README.md for the full walkthrough.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from . import attack_registry, command_registry, settings
from .telemetry_bus import TelemetryBus
from .transport.base import Transport
from .transport.pwncube_link import PwncubeTransport
from .transport.serial_link import SerialTransport
from .transport.zmq_link import ZmqTransport
from .watchdog import LinkWatchdog

log = logging.getLogger("pwnsat_c3.app")

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
FRONTEND_INDEX = FRONTEND_DIR / "index.html"
FRONTEND_LOGIN = FRONTEND_DIR / "login.html"
FRONTEND_PLATFORM = FRONTEND_DIR / "platform.html"
FRONTEND_PWNCUBE = FRONTEND_DIR / "pwncube.html"
ICON_PATH = settings.C3_ROOT / "icon.png"

PLATFORMS = ("flatsat", "pwncube")

watchdog = LinkWatchdog()
bus = TelemetryBus(watchdog)

# Every source this instance was able to configure (not necessarily
# connected yet -- e.g. "radio" is always configured but only actually
# receives packets once a GNU Radio bridge is running somewhere). Keys are
# "serial", "radio", or "cube". `active_source` is whichever one currently
# feeds the telemetry bus; switching it is just changing which source's
# packets get forwarded, no reconnect involved (see _make_relay below).
sources: Dict[str, Transport] = {}
active_source: str = ""
# Labels the operator manually released (see /api/transport/{label}/release)
# -- the watchdog in _connect_with_retry skips reconnecting these until
# /api/transport/{label}/reconnect clears the pause. Lets a wired transport
# ("cube" for PWNCUBE, "serial" for FlatSat) be handed off cleanly to a
# standalone USB script without fighting the watchdog for the interface,
# without restarting the whole uvicorn process (previously the only option
# was PWNSAT_C3_DISABLE_CUBE, which disables the source for the whole
# process instead of just pausing it).
_paused_sources: set[str] = set()
# Which platform the operator currently has selected -- separate from
# active_source because "radio" is a SHARED physical source (same
# RTL-SDR/HackRF, same GNU Radio bridge, same 918/916MHz -- PWNCUBE's RF
# params are identical to FlatSat's) that can carry either platform's
# bytes depending on which board is transmitting. telemetry_bus needs to
# know the PLATFORM, not just the source label, to decide whether to
# attempt AES decryption: PWNCUBE never encrypts, regardless of whether
# its bytes arrived via "cube" (USB) or "radio".
active_platform: str = "flatsat"
_SOURCE_PRIORITY = ["serial", "radio", "cube"]
# Which sources belong to which platform selector card -- api_platform uses
# this to flip active_source (and therefore _tx_transport()'s pick, see
# below) automatically when the operator switches craft, so the platform
# screen is not just a frontend skin: choosing PWNCUBE there really does
# route commands to the PWNCUBE board.
_PLATFORM_SOURCES = {"pwncube": ("cube", "radio"), "flatsat": ("serial", "radio")}
_seq_counter = 0


def _next_seq() -> int:
    global _seq_counter
    _seq_counter = (_seq_counter % 16383) + 1
    return _seq_counter


def _build_sources() -> Dict[str, Transport]:
    built: Dict[str, Transport] = {}
    serial_port = os.environ.get("PWNSAT_C3_SERIAL_PORT")
    if not serial_port:
        # No explicit override -- auto-detect which USB serial port is the
        # FlatSat's binary CCSDS link (as opposed to its plain-text debug
        # console, the other USB CDC interface the firmware exposes). See
        # port_detect.py's docstring: the two share one USB serial-number
        # string, so which one the OS names e.g. "fsat1" vs "fsat3" is not
        # stable across reconnects -- this probes for the real thing
        # instead of assuming a name.
        from .transport.port_detect import find_binary_link_port

        serial_port = find_binary_link_port()
        if serial_port:
            log.info("auto-detected FlatSat binary link on %s", serial_port)
        else:
            log.info(
                "no FlatSat serial port auto-detected (not connected, or "
                "already in use by another process) -- serial transport disabled"
            )
    if serial_port:
        baud = int(os.environ.get("PWNSAT_C3_SERIAL_BAUD", settings.DEFAULT_BAUD))
        built["serial"] = SerialTransport(serial_port, baud)
    radio_address = os.environ.get("PWNSAT_C3_ZMQ_ADDRESS", "tcp://127.0.0.1:5005")
    built["radio"] = ZmqTransport(radio_address)
    # Always configured, same as "radio" above: connect() just fails fast
    # with a clean error if no PWNCUBE is plugged in yet, and
    # _connect_with_retry keeps retrying every RECONNECT_INTERVAL_S -- so a
    # board plugged in after startup gets picked up without a restart
    # (plug-and-play by design), no separate detection path
    # needed.
    #
    # PWNSAT_C3_DISABLE_CUBE: opt out of building "cube" at all -- lets a
    # standalone USB attack script claim the board's USB interface without
    # C3's own watchdog fighting it for the connection.
    # C3 still shows PWNCUBE telemetry fine in this mode via "radio" (RF
    # downlink), it just can't send commands or read via USB itself.
    if not os.environ.get("PWNSAT_C3_DISABLE_CUBE"):
        built["cube"] = PwncubeTransport()
    if not built:
        raise RuntimeError(
            "no transport configured -- set PWNSAT_C3_SERIAL_PORT for USB, "
            "or check that a FlatSat/PWNCUBE board is connected"
        )
    return built


def _default_source(built: Dict[str, Transport]) -> str:
    for name in _SOURCE_PRIORITY:
        if name in built:
            return name
    raise RuntimeError("no transport sources available")


def _tx_transport() -> Optional[Transport]:
    """Commands/attacks always go out over a wired link (FlatSat's USB
    serial or PWNCUBE's USB gadget) -- never radio, which has no uplink
    flowgraph. Independent of which source is currently active for
    *viewing* telemetry.

    Prefers whichever wired source is actually connected right now (so with
    both a FlatSat and a PWNCUBE plugged in, commands follow whichever one
    is live rather than always favoring FlatSat); falls back to the fixed
    priority order if none are connected yet, same as before."""
    for name in ("serial", "cube"):
        t = sources.get(name)
        if t is not None and t.connected:
            return t
    for name in ("serial", "cube"):
        t = sources.get(name)
        if t is not None:
            return t
    return None


app = FastAPI(title="PWNSAT-C3", version="0.1.0")
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)


def require_login(request: Request) -> None:
    if not request.session.get("authenticated"):
        raise HTTPException(401, "not authenticated")


RECONNECT_INTERVAL_S = 3.0


async def _connect_with_retry(t: Transport, label: str) -> None:
    """Keeps retrying in the background instead of crashing the whole app if
    a source isn't reachable yet at startup -- the dashboard stays up and
    /api/status reports that source as "not connected" until it comes up,
    rather than uvicorn failing to bind at all.

    Also keeps watching AFTER a successful connect, for the lifetime of the
    app -- a previous version of this loop returned as soon as t.connect()
    succeeded once, so a transport that dropped mid-session (a USB hiccup,
    a standalone script briefly stealing the interface, a cable wiggle)
    never reconnected on its own; the only fix was a manual uvicorn
    restart. This happens often enough with PWNCUBE's "cube" transport
    (its USB gadget interface is easy to contend with) that it needs to be
    handled here, not treated as a rare edge case. Checking t.connected
    every RECONNECT_INTERVAL_S and only calling connect() when it's
    actually down makes this a real watchdog instead of a one-shot startup
    retry."""
    while True:
        if not t.connected and label not in _paused_sources:
            try:
                t.connect()
                log.info("%s transport connected: %s", label, t.description)
            except Exception as exc:  # noqa: BLE001 -- any transport can fail here
                log.warning(
                    "could not connect %s transport (%s: %s); retrying in %.0fs",
                    label, t.description, exc, RECONNECT_INTERVAL_S,
                )
        await asyncio.sleep(RECONNECT_INTERVAL_S)


def _make_relay(label: str):
    """Only forward a source's packets into the telemetry bus while it's the
    active one -- both sources stay connected in the background regardless,
    so flipping the switch is instant instead of a reconnect.

    Exception: PWNCUBE's "cube" (USB) transport always forwards, regardless
    of the display toggle. Its background telemetry reader (see
    backend/transport/pwncube_link.py's "Background telemetry reader"
    docstring) is what gives PWNCUBE parity with FlatSat's own always-on
    serial link -- some RF-only attacks legitimately need the RTL-SDR
    bridge stopped for the duration of the attack, which would otherwise
    starve every panel that depends on live telemetry (GS handshake, GS
    radar, ...) for that whole time if "cube" were gated the same way.
    FlatSat's sources (and PWNCUBE's own "radio") keep the exact original
    single-active-source behavior."""
    def relay(raw_spp: bytes) -> None:
        always_on_cube = active_platform == "pwncube" and label == "cube"
        if active_source == label or always_on_cube:
            bus.on_raw_packet(raw_spp, source=label, platform=active_platform)
    return relay


@app.on_event("startup")
async def on_startup() -> None:
    global sources, active_source
    bus.bind_loop(asyncio.get_running_loop())
    sources = _build_sources()
    active_source = _default_source(sources)
    for label, t in sources.items():
        t.on_telemetry(_make_relay(label))
        asyncio.create_task(_connect_with_retry(t, label))
    asyncio.create_task(watchdog.run(bus.broadcast, bus.reset_pulses))


@app.on_event("shutdown")
async def on_shutdown() -> None:
    for t in sources.values():
        t.disconnect()


@app.get("/login")
async def login_page() -> FileResponse:
    return FileResponse(FRONTEND_LOGIN)


@app.get("/icon.png")
async def icon() -> FileResponse:
    return FileResponse(ICON_PATH, media_type="image/png")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def api_login(req: LoginRequest, request: Request) -> dict:
    if req.username != settings.LOGIN_USERNAME or req.password != settings.LOGIN_PASSWORD:
        raise HTTPException(401, "invalid credentials")
    request.session["authenticated"] = True
    return {"ok": True}


@app.get("/api/logout")
async def api_logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/login")


@app.get("/platform")
async def platform_page(request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse("/login")
    return FileResponse(FRONTEND_PLATFORM)


class PlatformRequest(BaseModel):
    platform: str


async def _reset_link_state_and_broadcast() -> None:
    watchdog.reset()
    snap = watchdog.snapshot()
    await bus.broadcast({
        "type": "link_state",
        "state": snap.state,
        "last_telemetry_age_ms": snap.last_telemetry_age_ms,
    })


@app.post("/api/platform", dependencies=[Depends(require_login)])
async def api_platform(req: PlatformRequest, request: Request) -> dict:
    global active_source, active_platform
    if req.platform not in PLATFORMS:
        raise HTTPException(400, f"unknown platform: {req.platform!r}")
    request.session["platform"] = req.platform
    # active_platform (separate from active_source) is what telemetry_bus
    # actually keys its AES-bypass decision off of -- see its top-of-file
    # comment for why the source label alone isn't enough now that "radio"
    # is shared between both craft.
    active_platform = req.platform
    # Make the switch real, not just a frontend skin change: route the
    # active source (both viewing and, via _tx_transport()'s "cube"/"serial"
    # priority, commands) to whichever transport belongs to the newly
    # chosen craft, picking the first one this instance actually has
    # configured (see _PLATFORM_SOURCES).
    for name in _PLATFORM_SOURCES[req.platform]:
        if name in sources:
            active_source = name
            await _reset_link_state_and_broadcast()
            break
    return {"ok": True, "platform": req.platform, "active_source": active_source}


@app.get("/")
async def index(request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse("/login")
    platform = request.session.get("platform")
    if platform not in PLATFORMS:
        return RedirectResponse("/platform")
    if platform == "pwncube":
        return FileResponse(FRONTEND_PWNCUBE)
    return FileResponse(FRONTEND_INDEX)


@app.get("/api/status", dependencies=[Depends(require_login)])
async def api_status() -> dict:
    snap = watchdog.snapshot()
    active = sources.get(active_source)
    tx = _tx_transport()
    return {
        "active_source": active_source,
        "sources": {
            label: {"description": t.description, "connected": t.connected}
            for label, t in sources.items()
        },
        "transport": active.description if active else None,
        "connected": active.connected if active else False,
        "supports_tx": bool(tx is not None and tx.connected),
        "link_state": snap.state,
        "last_telemetry_age_ms": snap.last_telemetry_age_ms,
        "secure_link_enabled": snap.secure_link_enabled,
        "usb_debug_enabled": snap.usb_debug_enabled,
        "commands": command_registry.available_commands(),
        "attacks": attack_registry.available_attacks(),
    }


class TransportSwitchRequest(BaseModel):
    source: str


@app.post("/api/transport", dependencies=[Depends(require_login)])
async def api_transport(req: TransportSwitchRequest) -> dict:
    global active_source
    if req.source not in sources:
        raise HTTPException(400, f"source {req.source!r} is not configured on this instance")
    active_source = req.source
    # The aggregate link_state only tracks "age since any packet last
    # arrived", not which source produced it -- without resetting here,
    # switching away from a source that was actively receiving kept
    # showing "connected" off its stale freshness instead of reflecting
    # that the newly-selected source hasn't proven itself yet. Broadcast
    # immediately so the frontend doesn't wait for the watchdog's next
    # ~1s tick to see it.
    await _reset_link_state_and_broadcast()
    return {"ok": True, "active_source": active_source}


@app.post("/api/transport/{label}/release", dependencies=[Depends(require_login)])
async def api_transport_release(label: str) -> dict:
    """Disconnect one wired transport (e.g. "cube" for PWNCUBE, "serial"
    for FlatSat) and stop the watchdog from reconnecting it, freeing
    whatever hardware handle it holds (USB interface claim, serial port)
    for a standalone attack script to use directly. The RTL-SDR bridge and
    other sources are unaffected -- this only touches the one label given.
    Does not change active_source; if the released transport was active,
    /api/status will just show it disconnected until reconnected."""
    t = sources.get(label)
    if t is None:
        raise HTTPException(400, f"source {label!r} is not configured on this instance")
    _paused_sources.add(label)
    t.disconnect()
    await _reset_link_state_and_broadcast()
    return {"ok": True, "label": label, "connected": t.connected}


@app.post("/api/transport/{label}/reconnect", dependencies=[Depends(require_login)])
async def api_transport_reconnect(label: str) -> dict:
    """Undo /release: clear the pause and try to reconnect immediately
    (rather than waiting up to RECONNECT_INTERVAL_S for the watchdog's next
    tick). If the immediate attempt fails (e.g. a standalone script still
    has the interface claimed), the pause stays cleared and the watchdog
    keeps retrying in the background exactly as it does for any other
    disconnected transport."""
    t = sources.get(label)
    if t is None:
        raise HTTPException(400, f"source {label!r} is not configured on this instance")
    _paused_sources.discard(label)
    error: Optional[str] = None
    if not t.connected:
        try:
            t.connect()
        except Exception as exc:  # noqa: BLE001 -- any transport can fail here
            error = str(exc)
    await _reset_link_state_and_broadcast()
    return {"ok": error is None, "label": label, "connected": t.connected, "error": error}


class CommandRequest(BaseModel):
    command: str
    args: Dict[str, Any] = {}
    encrypt: bool = True
    seq: Optional[int] = None
    # Opt-in CCSDS secondary-header format pilot (ping only for now) -- see
    # command_registry.build_command(). Always cleartext; not related to
    # `encrypt` above.
    secured: bool = False


@app.post("/api/command", dependencies=[Depends(require_login)])
async def api_command(req: CommandRequest) -> dict:
    tx = _tx_transport()
    if tx is None or not tx.connected:
        raise HTTPException(503, "no TX-capable transport connected (USB serial required to send commands)")
    try:
        raw_spp = command_registry.build_command(
            req.command, req.args, req.encrypt, req.seq or _next_seq(), req.secured
        )
    except command_registry.UnknownCommand as exc:
        raise HTTPException(400, f"unknown command: {exc}") from exc

    from usb_tc_send import frame_usb  # local import: only needed for the echo hex

    framed = frame_usb(raw_spp)
    try:
        tx.send_tc(raw_spp)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    correlation_id = await bus.command_sent(req.command, raw_spp, framed, req.encrypt)
    return {"ok": True, "correlation_id": correlation_id, "raw_hex": raw_spp.hex(), "framed_hex": framed.hex()}


class AttackRequest(BaseModel):
    attack: str


@app.post("/api/attack", dependencies=[Depends(require_login)])
async def api_attack(req: AttackRequest) -> dict:
    tx = _tx_transport()
    if tx is None or not tx.connected:
        raise HTTPException(503, "no TX-capable transport connected (USB serial required to send attacks)")
    try:
        packets = attack_registry.build_attack(req.attack)
    except attack_registry.UnknownAttack as exc:
        raise HTTPException(400, f"unknown attack: {exc}") from exc

    from usb_tc_send import frame_usb

    steps = []
    for raw_spp in packets:
        framed = frame_usb(raw_spp)
        try:
            tx.send_tc(raw_spp)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        correlation_id = await bus.command_sent(req.attack, raw_spp, framed, encrypted=True)
        steps.append({"correlation_id": correlation_id, "raw_hex": raw_spp.hex(), "framed_hex": framed.hex()})
    return {"ok": True, "attack": req.attack, "steps": steps}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    if not ws.session.get("authenticated"):
        await ws.close(code=4401)
        return
    await bus.register(ws)
    try:
        while True:
            await ws.receive_text()  # clients don't send anything meaningful; just detect disconnect
    except WebSocketDisconnect:
        bus.unregister(ws)
