# PWNSAT-C3 — Technical Documentation

This is the living reference for everything in this folder: what each piece
does, how every script/module/function fits together, how to run the GUI
against real hardware over USB or the standalone radio receiver, and the
full scope of attacks reachable from the dashboard. Update this file
whenever a module, script, or route changes — it should always describe the
code as it actually is, not as it was when first written.

- Project name: **PWNSAT-C3**
- Scope: two satellite platforms, chosen after login on a mission-select
  screen (`/platform`) — **FlatSat** (RP2040, USB serial) and **PWNCUBE**
  (dual-core RV1106, USB gadget). Both also share a single RF receive path
  (RTL-SDR/HackRF, live via `gradio/pwnsat_rx_bridge.py` — see §1.4/§4
  `sources`). No GNU Radio uplink flowgraph exists yet, so commands can only
  be sent over a wired USB link today, never radio.
- Self-contained: everything under this folder is vendored locally
  (`pwnsat_tools/`, `gradio/`) — nothing here reaches outside the repo at
  runtime.
- Requires real hardware: a FlatSat or PWNCUBE board connected over USB (or
  RF for receive-only). There is no no-hardware mode.

---

## 1. Quick start (GUI)

### 1.1 Start it (real board over USB)

```shell
cd PWNSAT-C3
source .venv/bin/activate   # after the one-time `pip install -r requirements.txt`
uvicorn backend.app:app --app-dir .
```

No transport env vars needed for a plain USB run — `_build_sources()`
(`backend/app.py`) always tries to build every source it can:

- **FlatSat serial** — auto-detected by probing every enumerated serial
  port with a PING telecommand and checking for an `0xAA`-framed reply (see
  `backend/transport/port_detect.py`; this exists because the firmware's
  two USB CDC endpoints — the binary `USBRadioLink` and the plain-text debug
  `Serial` console — share one USB serial-number string, so which
  `/dev/tty.usbmodemXXXX` gets which role is not stable across reconnects).
  Override with `PWNSAT_C3_SERIAL_PORT=/dev/tty.usbmodemXXXX` to skip
  auto-detection.
- **PWNCUBE USB** (`cube`) — always attempted via `PwncubeTransport`
  (`backend/transport/pwncube_link.py`, `pyusb`, VID:PID `2207:0011`) unless
  `PWNSAT_C3_DISABLE_CUBE=1`. `connect()` just fails fast with a clean,
  retried-in-the-background error if no PWNCUBE is plugged in — same
  plug-and-play behavior as the other sources.
- **radio** (`ZmqTransport`) — always configured too (see §1.4); harmless
  with no GNU Radio bridge running.

If the transport isn't reachable yet at startup the app doesn't crash — it
retries in the background every few seconds and the browser shows a
disconnected/"NO SIGNAL" state until the link comes up. A board plugged in
after startup is picked up automatically (no restart) — `_connect_with_retry`
in `app.py` keeps retrying every source that isn't connected yet, for the
whole life of the process, not just at startup.

### 1.2 Log in, then pick a platform

Open `http://127.0.0.1:8000/`. You'll be redirected to `/login`.

Default credentials: **operator** / **pwnsat**. Override before using this
anywhere but a local rehearsal:

```shell
export PWNSAT_C3_USERNAME=your_operator_name
export PWNSAT_C3_PASSWORD=your_passphrase
export PWNSAT_C3_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

`PWNSAT_C3_SECRET_KEY` signs the session cookie. If left unset, a random key
is generated per process start, so every restart logs everyone out.

After logging in you land on `/platform` (`frontend/platform.html`), not the
dashboard directly — a mission-select screen with two cards, **FlatSat** and
**PWNCUBE**. `POST /api/platform {"platform": "flatsat"|"pwncube"}` stores
the choice in the session (`request.session["platform"]`) and also flips
`active_source` to the first source configured for that craft
(`_PLATFORM_SOURCES` in `app.py`: `pwncube` → `cube`/`radio`, `flatsat` →
`serial`/`radio`), so picking a card really does route both viewing *and*
commands to that board, not just the UI skin. `GET /` then serves
`frontend/pwncube.html` or `frontend/index.html` depending on the session's
platform. Logging out clears the platform choice along with the session —
the next login always returns to `/platform`.

### 1.3 Using the dashboard

Once logged in and a platform is selected, the page has these panels
(FlatSat's `index.html` and PWNCUBE's `pwncube.html` share the same visual
system and panel set — PWNCUBE dropped GPS/Nav, Ground station, and the
world-map/GS-radar panels early on, then regained all of them once the
corresponding APIDs were ported to its firmware; see `pwncube.html`'s own
header comment):

| Panel | What it shows |
| --- | --- |
| **Effects monitor** (top, full width) | The link-state watchdog's current verdict: `LINK ACTIVE` (green), `WEAK SIGNAL` (amber, flickers), `NO SIGNAL` (red), or `REBOOT DETECTED` (red flash, one-shot). This is the "does the attack landed" indicator — it reacts the same way regardless of whether a command came from this dashboard, a HackRF, or the SpaceCAN serial console, because it only watches telemetry arriving on this dashboard's own transport connection. |
| **Mission state** | Mission mode, uptime, beacon interval, firmware version, secure-link/payload-armed/USB-debug flags — decoded from the latest `STATUS` (0x0C) telemetry. |
| **Thrusters** | Two gauges (0–255) for thruster 0/1, decoded from `STATUS`. Each gauge flashes immediately when you send a `SET_THRUSTER` command (before the next real telemetry frame confirms it). |
| **GPS / Nav** | Fix/connected/NMEA/time-valid indicator lights, lat/lon/altitude, UTC clock, satellite count — decoded from `NAV` (0x0E). |
| **Ground station** | Mode-enabled/within-range/auth-active/gate-open flags, distance, session/handshake countdowns, challenge value, auth phase — decoded from `GS_MODE`/`GS_ACCESS`/`GS_STATUS`. |
| **Operations** | Quick buttons (PING, GET_STATUS, GET_NAV, GS_STATUS) plus small forms for SET_THRUSTER and SET_MISSION_MODE. These build and send **legitimate** telecommands. |
| **Attack (rehearsal)** | One button per canned attack from `attack_registry.py` (see §6 for the full list), each with a one-line description of which documented finding it exercises. These are for rehearsing/testing against your own board without a HackRF — the physically-realistic, RF-driven versions of the equivalent attacks are run separately, over RF/serial console, and are documented in each platform's own repository (see §6). |
| **Telemetry / events** | A scrolling log of every websocket message: decoded telemetry, link-state transitions, command echoes, and decode errors. |

Logging out (top-right link) clears the session and redirects to `/login`.

### 1.4 Sources, and switching between them at runtime

Unlike a single fixed transport, the app builds every source it can at
startup (`_build_sources()`) and holds them all open simultaneously —
switching which one feeds the UI (`POST /api/transport {"source": "..."}`)
is instant, not a reconnect, because every configured source keeps
receiving in the background regardless of which one is "active" (see
`_make_relay()` in `app.py`). The mission-select screen's platform choice
also flips `active_source` automatically (§1.2).

| Source label | Platform | Direction | How it's built |
|---|---|---|---|
| `serial` | FlatSat | TX + RX | `SerialTransport`, auto-detected port or `PWNSAT_C3_SERIAL_PORT` (§1.1). |
| `cube` | PWNCUBE | TX + RX | `PwncubeTransport` (`pyusb`), always attempted unless `PWNSAT_C3_DISABLE_CUBE=1` (§1.1, §4). |
| `radio` | both (shared) | RX only | `ZmqTransport` against `PWNSAT_C3_ZMQ_ADDRESS` (default `tcp://127.0.0.1:5005`) — a live ZMQ SUB client of `gradio/pwnsat_rx_bridge.py`, which must already be running separately under the Python that has `gnuradio`/`soapy` importable (see §8). Always configured; harmless with no bridge running. |

Every decoded downlink packet, regardless of source, flows into the same
`TelemetryBus`/watchdog/websocket pipeline — no dashboard code downstream of
`Transport` cares which source produced the bytes (`telemetry_bus.py` does
branch on the *platform* though, to decide whether to attempt AES decryption
— PWNCUBE never encrypts, FlatSat's full firmware does).

`radio` cannot send commands: no GNU Radio uplink flowgraph exists in this
repo, so `send_tc()` raises a clear `RuntimeError` that `/api/command` and
`/api/attack` turn into a 503, and the frontend greys out the
Operations/Attack panels entirely (`Transport.supports_tx == False`, see
§4). `_tx_transport()` always prefers a connected wired source (`serial` or
`cube`) — so switching the dashboard to `radio` to watch a passive capture
doesn't change what a command button would send over, if a wired link is
also up.

**Handing a wired interface to a standalone script.** `POST
/api/transport/{label}/release` disconnects one source (e.g. `cube`) and
stops the background watchdog from reconnecting it, freeing the USB
interface for a standalone attack script to claim directly — without
restarting the whole process. `POST /api/transport/{label}/reconnect`
undoes that. This replaces an earlier workaround
(`PWNSAT_C3_DISABLE_CUBE` set for the whole process just to run one
script).

---

## 2. Configuration reference (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `PWNSAT_C3_SERIAL_PORT` | *(auto-detected)* | FlatSat's binary USB CDC device path. Skips `port_detect.py`'s auto-probe when set. |
| `PWNSAT_C3_SERIAL_BAUD` | `921600` | FlatSat serial baud rate. |
| `PWNSAT_C3_DISABLE_CUBE` | *(unset)* | Set to `1` to skip building the `cube` (PWNCUBE USB) source entirely — e.g. so a standalone attack script can claim the USB interface without C3's watchdog fighting it for the connection. |
| `PWNSAT_C3_ZMQ_ADDRESS` | `tcp://127.0.0.1:5005` | ZMQ SUB address the `radio` source connects to — must match `gradio/pwnsat_rx_bridge.py`'s `--address` (§1.4/§8). |
| `PWNSAT_C3_USERNAME` | `pwnsat` | Dashboard login username. |
| `PWNSAT_C3_PASSWORD` | `pwnsat` | Dashboard login password. |
| `PWNSAT_C3_SECRET_KEY` | *(random per process)* | Session-cookie signing key. |
| `PWNSAT_C3_ASSUME_ENCRYPTED` | `1` | Set to `0` to assume FlatSat telemetry starts out plaintext (see `backend/settings.py`'s `ASSUME_SECURE_LINK_ENABLED` comment) — only relevant against firmware builds without `secure_link.cpp`. |

Watchdog timing (`STALE_AFTER_S=30`, `LOST_AFTER_S=60`,
`HEARTBEAT_INTERVAL_S=5`, `RESET_UPTIME_TOLERANCE_S=2`) and the flash-window
maintenance constants (`DEFAULT_FLASH_WINDOW_ID=0xA5`,
`DEFAULT_FLASH_UNLOCK_TAG=0xC35A`, `DEFAULT_GS_AUTH_KEY=0xC0DEFACE`) live as
plain constants in `backend/settings.py`, not environment variables — edit
that file to change them.

---

## 3. Architecture / data flow

```
FlatSat (USB)   PWNCUBE (USB gadget)   RTL-SDR/HackRF
     |                  |             (gradio/, separate
framed TM         shell CLI text        process) -> ZMQ
(0xAA+SPP)      ("radio_test tlm")           |
     |                  |                    |
SerialTransport  PwncubeTransport      ZmqTransport
     \__________________|____________________/
                                \/
                          Transport (base.py)
                    (sources: serial / cube / radio, §1.4)
                                |
                     TelemetryBus.on_raw_packet(source, platform)
                (decrypt if flatsat, tm_decoder.decode(platform=...))
                                |
              WebSocket broadcast -> browser (index.html or pwncube.html,
                                               chosen by session platform)
                                |
                          LinkWatchdog
              (STALE/LOST timers, uptime-rollback -> reset_detected)

Commands: dashboard button -> POST /api/command or /api/attack
   -> command_registry.py / attack_registry.py build raw SPP bytes
   -> _tx_transport() picks a connected wired source (serial/cube)
   -> Transport.send_tc() frames + writes (or, for PwncubeTransport,
      re-encodes as a `radio_test tcsend` shell command)
```

Everything above the `Transport` line (decoder, command/attack registries,
websocket bus, watchdog, routes) is transport-agnostic — it only ever sees
raw SPP bytes in and JSON out. `PwncubeTransport` is the one place that
translates between "raw SPP bytes" and PWNCUBE's actual wire reality (a
text-mode debug shell CLI, not a binary framed link) — see its own
docstring and the `transport/pwncube_link.py` entry below.

---

## 4. Backend reference (`backend/`)

### `settings.py`
Adds `pwnsat_tools/` to `sys.path` (once, at import time) and holds every
constant listed in §2, plus `SCRIPTS_DIR`/`C3_ROOT` path resolution.

### `transport/base.py`
`Transport` (ABC): `connect()`, `disconnect()`, `connected` (property),
`send_tc(raw_spp: bytes)`, `description` (property), `on_telemetry(callback)`
to register the function called with each deframed raw SPP telemetry packet.

### `transport/serial_link.py`
`SerialTransport(port, baud=921600)`. Opens a real `serial.Serial`, runs a
background reader thread that accumulates bytes and calls
`usb_tc_send.iter_usb_sync_packets()` to peel off complete telemetry frames,
emitting each via the registered callback. Writes go through
`usb_tc_send.frame_usb()`, serialized behind the same lock the reader thread
uses.

### `transport/port_detect.py`
`find_binary_link_port(candidates=None) -> Optional[str]` — auto-detects
which enumerated serial port is FlatSat's binary CCSDS link, used when
`PWNSAT_C3_SERIAL_PORT` isn't set. Exists because the firmware's two USB CDC
endpoints (binary `USBRadioLink` and plain-text debug `Serial`) share one
USB serial-number string, so which `/dev/tty...` gets which role isn't
stable across reconnects. Strategy: send a PING telecommand to every
candidate port and check for an `0xAA`-framed reply (`_probe_port`) — not
name/VID/PID filtering, since the whole point is not to assume a naming
pattern that's already been observed to break.

### `transport/pwncube_link.py`
`PwncubeTransport` — talks to a PWNCUBE board over its USB gadget interface
(`pyusb`, vendor-specific bulk pair, VID:PID `2207:0011`, not CDC-ACM).
Unlike every other transport, PWNCUBE has no raw binary SPP link exposed
over USB at all — commands only ever reach the satellite via the
RT-Thread/RISC-V core's own `radio_test tcsend <apid_hex> <payload_hex>` CLI,
reached from the Cortex-A7 Linux side's debug shell console over `rpmsg`.
So `send_tc()` still honors the `Transport` ABC contract (raw SPP bytes in)
but internally decodes those bytes with `spp_tools.decode_packet` and
re-encodes them as that CLI's text syntax, instead of writing framed bytes
to a wire.

- `connect()` claims the USB interface, then navigates the board's
  `pwnsat_console` boot menu into "3) Debug Shell" and confirms a live
  prompt via an echo marker — done blind every time since the board's menu
  state at connection time isn't known (fresh boot, mid-menu, already in a
  shell from a previous session all look different).
- Telemetry arrives by running `radio_test tlm` in the background **on the
  board itself**, redirected to a file, polled every ~2s over a second shell
  command (`cat` + a byte offset) and re-parsed into raw SPP frames — this
  (not a foreground blocking read) is what lets PWNCUBE's dashboard show
  continuously-updating telemetry over USB independent of whatever the RF
  side is doing, matching FlatSat's always-on serial link.
- All shell interaction (writes + reads) is serialized behind one lock
  spanning each full command's write→sleep→drain sequence, since the
  background telemetry poller and a foreground `send_tc()` both drive the
  same shell concurrently.

### `transport/zmq_link.py`
`ZmqTransport(address)` — real RX transport, live against `gradio/`. Opens a
ZMQ SUB socket against `pwnsat_rx_bridge.py`'s PUB address (default
`tcp://127.0.0.1:5005`), runs a background reader thread that blocks on
`sock.recv()` with a 500ms timeout (so `disconnect()` can cleanly join it) and
`_emit()`s each message straight through — LoRa's own packet framing already
gives one complete raw SPP packet per `recv()`, no byte-stream reassembly like
`serial_link.py` needs. `send_tc()` raises `RuntimeError` unconditionally: no
GNU Radio TX flowgraph exists in this repo yet, so there is no uplink to send
through. `supports_tx` returns `False` (see `base.py` below) so the REST layer
and frontend both know not to offer commands over this transport.

### `transport/base.py` — `supports_tx`
Every transport exposes `supports_tx: bool` (default `True` on the ABC,
overridden to `False` only by `ZmqTransport`). `/api/status` echoes it
verbatim; `frontend/index.html` toggles a `no-tx` class on the Operations and
Attack panel containers from it, which greys them out with an explanatory
note instead of leaving buttons that always 503. `api_command()`/`api_attack()`
in `app.py` also wrap `transport.send_tc()` in `try/except RuntimeError` and
re-raise as `HTTPException(503, ...)`, so hitting the REST endpoints directly
(e.g. with curl) gets a clean error too, not a raw 500.

### `tm_decoder.py`
The structured-telemetry decoder — the main piece of new logic in this
project (nothing before it parsed TM payloads into fields, only
hexdump/decrypt existed).

- Flag decoders: `mission_flags(byte)`, `gps_flags(byte)`, `gs_flags(byte)` —
  bitmasks copied 1:1 from `src/mission.h`.
- `crc8(data)` — CRC-8 poly `0x07` init `0x00`, matching
  `src/worker.cpp:crc8_compute` exactly (used to validate FLASH/FLASH_READ
  chunk checksums against the firmware's real algorithm).
- One `@dataclass` per TM type (`MissionStatusTM`, `MissionModeTM`,
  `PayloadStatusTM`, `NavTM`, `GsModeTM`, `GsAccessTM`, `GsStatusTM`,
  `FirmwareVersionTM`, `AesConfigTM`, `DebugConfigTM`, `PingAckTM`, `ErrorTM`,
  `FlashChunkTM`, `FlashReadTM`, `BroadcastEchoTM`), each with `.as_dict()`
  that also expands flag bytes into named booleans and adds convenience
  fields (`fw_version`, `latitude_deg`, etc).
- `decode_<name>(data: bytes) -> <Dataclass>` — one function per APID, each
  the exact inverse `struct.unpack` of the firmware's real TM builder in
  `src/worker.cpp` (verified directly against that source).
- `APID_TM_DECODERS: dict[int, Callable]` and `APID_TM_NAMES: dict[int, str]`
  — the registries `decode(apid, plaintext_data)` looks up; returns `None`
  for any APID without a structured decoder yet (caller falls back to raw
  hex).

### `command_registry.py`
`build_command(command, args, encrypt, seq) -> bytes` — resolves through
`usb_tc_send.APID_NAMES` and `usb_tc_send.build_wire_payload()` (reused
as-is, including firmware quirks like the finding-#9 1-byte-payload padding
— this tool reproduces real firmware behavior, it does not "fix" it).
`DEFAULT_ARGS` supplies sane defaults for every optional argument
(`thruster_id`, `power`, `seconds`, `frequency`, `message`, `mission_mode`,
`aes_mode`, `debug_mode`, `gs_comm_mode`, `handshake`, `challenge`,
`auth_key`, `offset`, `read_length`, `window_id`, `unlock_tag`).
`available_commands()` returns the sorted list of command names for
`/api/status`. Raises `UnknownCommand` for anything not in `APID_NAMES`.

### `attack_registry.py`
Thin adapter over `sim_attack.make_attack()` — see §6 for the full attack
list and finding mapping. `build_attack(name) -> list[bytes]`,
`available_attacks() -> list[{name, description}]`. Raises `UnknownAttack`
for anything not in `ATTACK_NAMES`.

### `telemetry_bus.py`
`TelemetryBus`: holds the set of connected websocket clients.
`on_raw_packet(raw_spp)` is the thread-safe entry point a `Transport`'s
background thread calls — it schedules `_handle_packet()` onto the bound
asyncio loop via `bind_loop()`. `_handle_packet` decrypts if
`watchdog.payload_is_encrypted`, decodes via `tm_decoder`, feeds the watchdog
(`record_status`/`record_aes_config`/`record_debug_config`), and broadcasts a
`telemetry` (or `decode_error`) websocket message. `command_sent(...)`
broadcasts a `command_sent` message with a generated `correlation_id` so the
UI can react to a send immediately, ahead of the next confirming telemetry
frame.

### `watchdog.py`
`LinkWatchdog` — the state machine behind the effects monitor.
`record_packet()` bumps the last-telemetry timestamp on every packet.
`record_status(fields)` checks for an `uptime_s` rollback (reboot signal) and
tracks `secure_link_enabled`/`usb_debug_enabled` from `STATUS` flags.
`record_aes_config`/`record_debug_config` update the same two flags from
their respective ack telemetry. `payload_is_encrypted` (property) is what
`telemetry_bus` asks before attempting decryption. `run(broadcast,
reset_pulses)` is the background asyncio task: ticks roughly once a second,
computes `connected`/`stale`/`lost` from telemetry age against
`STALE_AFTER_S`/`LOST_AFTER_S`, and broadcasts a `link_state` message on
every state change plus at least every `HEARTBEAT_INTERVAL_S` regardless (so
a client that connects mid-`stale` gets the right picture immediately), and
forwards one-shot `reset_detected` pulses queued by `telemetry_bus`.

### `app.py`
FastAPI app (`title="PWNSAT-C3"`). Routes:

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /login` | none | Serves `frontend/login.html`. |
| `POST /api/login` | none | Checks credentials, sets `request.session["authenticated"]`. |
| `GET /api/logout` | none | Clears session (including platform choice), redirects to `/login`. |
| `GET /platform` | session | Serves `frontend/platform.html`, the mission-select screen. |
| `POST /api/platform` | session | Sets `request.session["platform"]`, flips `active_source` to that craft's first configured source (§1.2). |
| `GET /` | session + platform | Serves `frontend/pwncube.html` or `frontend/index.html` depending on session platform; redirects to `/login` or `/platform` if either is missing. |
| `GET /api/status` | session | Active/all sources' description + connected state, aggregate link state, `supports_tx`, available commands/attacks. |
| `POST /api/transport` | session | Switches `active_source` to another already-configured source, resets link state (§1.4). |
| `POST /api/transport/{label}/release` | session | Disconnects one source and pauses its auto-reconnect, freeing the interface for a standalone script (§1.4). |
| `POST /api/transport/{label}/reconnect` | session | Undoes `/release`, reconnects immediately. |
| `POST /api/command` | session | Builds + sends a legitimate telecommand over `_tx_transport()`'s pick. |
| `POST /api/attack` | session | Builds + sends a canned attack's packet sequence. |
| `WS /ws` | session | Live telemetry/link-state/command-echo/decode-error stream. |

`SessionMiddleware` (Starlette, `itsdangerous`-signed cookie) gates
everything except `/login`/`/api/login`. `_build_sources()` builds every
source it can (§1.1/§1.4) rather than picking one at startup;
`_connect_with_retry()` runs as a background task per source from
`on_startup` — if a source isn't reachable yet, it logs a warning and keeps
retrying every `RECONNECT_INTERVAL_S` (3s) **for the whole lifetime of the
app**, not just at startup, so a source that drops mid-session (a USB
hiccup, a standalone script briefly stealing the interface) reconnects on
its own instead of needing a manual `uvicorn` restart. `_make_relay()`
forwards a source's packets into the telemetry bus only while it's the
active one, except PWNCUBE's `cube` source, which always forwards regardless
of the display toggle (so GS-handshake/radar-style panels that depend on
live telemetry don't starve during an RF-only attack that needs the SDR
bridge stopped).

---

## 5. Frontend reference (`frontend/`)

### `login.html`
Self-contained login page: username/password form posting to `/api/login`,
an animated canvas starfield background (`prefers-reduced-motion`-aware), a
shake animation on failed login. Redirects to `/` on success.

### `platform.html`
The mission-select screen served at `/platform`. Two cards ("FlatSat",
"PWNCUBE"), each `POST`ing to `/api/platform` on click and redirecting to
`/` on success. Shares the same starfield-background visual system as
`login.html`/`index.html`.

### `index.html`
Self-contained FlatSat dashboard (no build step): the panels described in
§1.3, a shared starfield background, WebSocket client (`connectWs()`,
auto-reconnect every 2s on close), and `fetch()`-based
`sendCommand()`/`sendAttack()` helpers posting to
`/api/command`/`/api/attack`. `loadStatus()` populates the attack-button
list from `/api/status` and redirects to `/login` on a 401.

### `pwncube.html`
The PWNCUBE equivalent of `index.html` — same visual system (green accent
instead of amber, matching its card on `platform.html`) and the same panel
set once STATUS/MISSION_MODE/PAYLOAD_STATUS/GS_MODE/GS_ACCESS/GS_STATUS
telemetry got ported to PWNCUBE's firmware under the same APIDs FlatSat
uses (some panels, including the ground-track world map and GS-range radar,
were dropped early when PWNCUBE had no firmware backing them yet, then
restored once it did — see the file's own header comment for the detail).
Kept as a fully separate HTML file rather than a single dashboard with
`data-platform` toggles, since the two craft's panel sets diverged enough
during development that a shared template stopped being the simpler option.

---

## 6. Attack scope (dashboard-reachable)

Every attack below is a **canned, pre-built packet sequence** sent over
whichever wired source is active (`serial`/`cube`) — no HackRF required to
rehearse these against your own board. Finding numbers below reference
FlatSat's own findings catalog, published in the FlatSat firmware repo, not
this one; PWNCUBE shares the same command APIDs (0x01–0x07) byte-for-byte,
so the same registry works against either platform once a wired PWNCUBE
source is connected, but PWNCUBE's own finding numbers and attack-vector
writeups live in its own repo/wiki
([PWNCUBE](https://github.com/Pwnsat/PWNCUBE)), not this table.

| Attack name | Finding(s) | What it does |
| --- | --- | --- |
| `reset-dos` | #16 | Unauthenticated `RESETC` — reboots the board. |
| `firmware-disclosure` | #21 | `SEND_FW` with no authentication. |
| `thruster-control` | #17 | `SET_THRUSTER` to full power with no authentication. |
| `beacon-flood` | #18 | `SET_BEACON_RATE=0` — floods the downlink. |
| `broadcast-underflow` | #10 (critical) | 1-byte `BROADCAST_MSG` — integer underflow, crashes the board. |
| `truncated-spp` | #7 | Declared SPP length larger than the real payload. |
| `flash-block` | #19 | `FLASH` dump — exfiltrates the embedded blob, blocks other telemetry meanwhile. |
| `replay` | #5 | Sends the exact same `PING` packet twice. |
| `status-recon` | #21 | `SEND_FW` + `STATUS` + `NAV` + `PAYLOAD_STATUS`, no auth. |
| `aes-downgrade` | #11 | Cleartext `AES_CONFIG(0)` — disables the secure link without the key. |
| `mission-mode-abuse` | #6 | Forces PAYLOAD mode, then abuses `BROADCAST_MSG` as an RF relay. |
| `gs-handshake-start` | #14 (setup step) | Requests a ground-station challenge. |

The physically-realistic, RF-driven versions of a subset of these (plus GPS
spoofing and the two SpaceCAN bus attacks) are out of scope for this
dashboard entirely — SpaceCAN is reached via the firmware's own debug
serial console, not radio — and are covered instead by standalone attack
scripts published in each platform's own repo (FlatSat's for FlatSat,
[PWNCUBE](https://github.com/Pwnsat/PWNCUBE)'s for PWNCUBE), not this one:
command injection via radio (#17/#13), fuzzing crash (#10), replay (#5),
GPS spoofing (#15), SpaceCAN command injection (#23), SpaceCAN bus-off
(#30). The FlatSat repository documents the full per-attack root-cause
writeups; this dashboard only exposes the rehearsal packet sequences.

---

## 7. Vendored tools reference (`pwnsat_tools/`)

Copied in from the wider project, unmodified, so this folder is
self-contained. None of this is re-derived — it's imported directly.

| File | Purpose |
| --- | --- |
| `spp_tools.py` | SPP/CCSDS codec: `build_primary_header`, `build_tc`, `build_tm`, `decode_packet(raw) -> DecodedPacket`, `hexdump`, `print_packet`, `APIDS` name table. |
| `pwnsat_crypto.py` | `encrypt_payload`/`decrypt_payload` — AES-128-ECB-with-length-prefix, matching `src/secure_link.cpp` exactly (hardcoded key `"PWNsatLabKey1234"`). |
| `usb_tc_send.py` | `frame_usb` (TC framing), `iter_usb_sync_packets` (TM deframing), `build_wire_payload`/`build_logical_payload` (per-APID payload construction), `compute_gs_response`; also a standalone CLI for sending one TC over a real serial port and printing the decoded/decrypted response. |
| `sim_attack.py` | `make_attack(name) -> list[bytes]` — the canned attack packet sequences `attack_registry.py` exposes (§6), built from the same SPP/AES primitives above. |
| `zmq_tc_send.py` | Phase-2 radio TX helper: builds a TC and pushes its hex string over ZMQ PUSH to a GNU Radio "ZMQ PULL Message Source" block. No corresponding TX flowgraph exists in this repo yet. |

---

## 8. Radio bridge reference (`gradio/`)

The passive downlink receiver. Feeds the dashboard live via `ZmqTransport`
when run with the `radio` source active (§1.4), or can be used entirely
standalone (prints decoded packets to the terminal) independent of the
dashboard. SDR-agnostic via GNU Radio's native `gnuradio.soapy` blocks (not
`gr-osmosdr` — avoided to skip an extra from-source build): same script and
flowgraph for an RTL-SDR or a HackRF, selected with `--device-args`
(`rtlsdr` / `hackrf`, a SoapySDR driver string) — auto-detected from
connected hardware if omitted.

| File | Purpose |
| --- | --- |
| `pwnsat_lora_rx.py` | `PwnsatLoraRX(gr.top_block)` — the flowgraph: `soapy.source` → `freq_xlating_fir_filter_ccc` (decimates hardware rate down to the LoRa channel rate) → `gnuradio.lora_sdr` LoRa RX → ZMQ pub sink. Constructor takes `device_args`, `frequency`, `bandwidth`, `zmq_address`, `spread_factor`, `rf_gain`, `if_gain`, `bb_gain`, `source_samp_rate` — `device_args` in particular **must** go through the constructor, since Soapy opens the physical device once, at construction, and can't be repointed afterward. |
| `pwnsat_lora_rx.grc` | GNU Radio Companion source for the above — edit here and regenerate if changing the signal-processing design. |
| `pwnsat_rx_bridge.py` | CLI control script: `--device-args`, `--frequency`, `--bandwidth`, `--spread_factor`, `--address` (ZMQ), `--rf-gain`/`--if-gain`/`--bb-gain`, `--source-samp-rate`, `--output-file` (raw length-prefixed capture), `--pcap-output-file`. Subscribes to the flowgraph's ZMQ PUB socket and hexdumps every decoded packet. Must run under the Homebrew Python that has `gnuradio`/`gnuradio.soapy`/`gnuradio.lora_sdr` importable, NOT the dashboard's own `.venv` — see the module docstring in `backend/transport/zmq_link.py`. |

**Hardware sample rate vs. LoRa channel rate.** RTL-SDR can sample directly at
the LoRa channel rate (`bandwidth`, 250 kHz by default) — `source_samp_rate`
defaults to `bandwidth` for it. HackRF's ADC has a hard minimum of 1 MSps and
rejects anything lower (`ValueError: Unsupported sample rate`), so
`source_samp_rate` defaults to 2,000,000 Hz whenever `--device-args hackrf`,
and the flowgraph runs `freq_xlating_fir_filter_ccc` at
`decim = source_samp_rate // bandwidth` (8, at the defaults) to bring it down
to the 250kHz the LoRa demodulator expects. `source_samp_rate` must be an
exact integer multiple of `bandwidth`, whatever both are set to.

**Gain stage naming differs by device.** RTL-SDR exposes one tuner gain
(`--rf-gain`, tried first). HackRF splits gain into an LNA stage and a VGA
stage; the flowgraph tries Soapy gain names `IF`/`LNA` for `--if-gain` and
`BB`/`VGA` for `--bb-gain` in that order (`_apply_if_gain`/`_apply_bb_gain`),
so the same three CLI flags work unmodified across both devices without the
caller needing to know Soapy's per-driver naming.

Full walkthrough, requirements, and worked examples: `gradio/README.md`.

---

## 9. Known open findings

- **No downlink signal ever observed over the air.** Extensive testing
  against the real FlatSat with two independent SDRs (RTL-SDR, then
  HackRF), across multiple gain settings and frequencies around 916 MHz,
  never showed any signal above the noise floor — the flowgraph, ZMQ
  transport, and dashboard pipeline described in §1.4/§8 are all verified
  working correctly (confirmed end-to-end via USB and via direct GNU Radio
  construction against real hardware); what's missing is the actual RF energy
  arriving at either receiver. The leading hypothesis is firmware-side:
  `src/rdownlink.cpp` never calls `setOutputPower()` on the downlink radio,
  so it defaults to RadioLib's stock 10dBm, versus the uplink radio's
  explicit 22dBm. Getting two different SDRs to the same null result rules
  out a receiver-specific problem but doesn't confirm this is the sole cause.
  Not yet fixed — firmware changes are made only with the user's explicit
  go-ahead.

---

## 10. Tests

```shell
cd PWNSAT-C3
python3 -m pytest backend/tests -v
```

- `test_usb_framing.py` — edge cases for `iter_usb_sync_packets` (split
  reads, back-to-back packets, a payload that legitimately contains a
  `0xAA` byte). Passes with no hardware connected.
