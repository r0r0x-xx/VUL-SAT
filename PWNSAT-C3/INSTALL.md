# Installing PWNSAT-C3

This covers three independent tiers, from lightest to heaviest:

1. **Core dependencies** — Python only, common to every tier below.
2. **FlatSat USB serial** — same install as core, plus OS-level
   permission/driver setup to talk to a real FlatSat board over USB.
3. **PWNCUBE USB** — same install as core, plus `libusb` and (on Linux) a
   udev rule, to talk to a real PWNCUBE board over its USB gadget interface.
4. **RF receive path** (optional) — GNU Radio + SoapySDR, a separate,
   heavier install, only needed if you're feeding the dashboard from an
   RTL-SDR/HackRF instead of (or in addition to) USB. Shared between both
   platforms — one bridge process, either board's downlink.

A real FlatSat or PWNCUBE board is required to run the dashboard — pick
whichever hardware you actually have and set up its matching tier. The
dashboard runs fine with only a subset of sources configured; anything not
set up simply doesn't show up as connected in `/api/status`.

Tested on Ubuntu 22.04/24.04 and macOS (Apple Silicon and Intel).

---

## 1. Core dependencies (Ubuntu and macOS)

### Requirements

- Python 3.10 or newer (3.11/3.12/3.13 all confirmed working).
- `pip` and `venv` (usually bundled with Python; see OS-specific notes below
  if not).

### Ubuntu

```shell
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### macOS

Install [Homebrew](https://brew.sh) first if you don't have it, then:

```shell
brew install python git
```

(macOS ships a system Python, but it's frequently old/restricted — use the
Homebrew one.)

### Both: clone and install

```shell
git clone https://github.com/Pwnsat/PWNSAT-C3 PWNSAT-C3
cd PWNSAT-C3
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Verify: run the test suite

```shell
source .venv/bin/activate
python3 -m pytest backend/tests -v
```

Should pass with no hardware connected — it exercises the USB-framing logic
against synthetic data. Once this passes, move on to §2 or §3 below to
connect a real board and verify the dashboard end to end.

---

## 2. FlatSat USB serial (real board)

The Python side needs nothing beyond what step 1 already installed
(`pyserial` is in `requirements.txt`). What differs by OS is **who is
allowed to open the serial device**.

### Ubuntu — serial port permissions

On Linux, USB-serial devices show up as `/dev/ttyACM*` or `/dev/ttyUSB*` and
are owned by the `dialout` group by default. Add your user to it once:

```shell
sudo usermod -aG dialout $USER
```

Then **log out and back in** (group membership changes don't apply to
already-open sessions). Confirm it took effect:

```shell
groups | grep dialout
```

Plug in the board and find its device node:

```shell
ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null
# or, to watch it appear live:
dmesg -w   # then plug the board in, Ctrl-C once you see it
```

You don't need to figure out which of the two enumerated ports is the
binary link and which is the debug console yourself —
`backend/transport/port_detect.py` auto-detects it by probing (§1.2 of
[`DOCUMENTATION.md`](DOCUMENTATION.md)). Set `PWNSAT_C3_SERIAL_PORT` only if
you want to skip that probe.

### macOS — serial port permissions

macOS doesn't require a group change for USB-serial access, but you do need
the right USB-CDC driver for the board's USB-to-serial chip (most RP2040
boards enumerate as a native CDC-ACM device and need no extra driver at
all; boards using a CP210x/CH340 bridge chip need Silicon Labs' or WCH's
driver installed once). Plug in the board and list candidates:

```shell
ls /dev/tty.usb* /dev/cu.usb*
```

### Both: run against the real board

```shell
source .venv/bin/activate
uvicorn backend.app:app --app-dir .
```

No transport flags needed — the FlatSat serial port is auto-detected. To
pin it explicitly instead:

```shell
PWNSAT_C3_SERIAL_PORT=/dev/ttyACM0 uvicorn backend.app:app --app-dir .
```

(Substitute the actual device path — `/dev/tty.usbmodemXXXX` on macOS.)

---

## 3. PWNCUBE USB (real board)

PWNCUBE has no CDC-ACM serial port — its USB gadget interface is a
vendor-specific bulk pair, accessed via `pyusb` (already in
`requirements.txt`) on top of `libusb`. `libusb` itself is a system
library, not pip-installable.

### Ubuntu

```shell
sudo apt install -y libusb-1.0-0
```

Non-root processes can't open arbitrary USB devices by default — add a udev
rule granting access to PWNCUBE's VID:PID (`2207:0011`):

```shell
sudo tee /etc/udev/rules.d/99-pwncube.rules > /dev/null <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="2207", ATTR{idProduct}=="0011", MODE="0666"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Unplug and replug the board after adding the rule (a running `udevadm
trigger` re-applies rules to already-connected devices too, but a fresh
plug is the most reliable way to confirm it took).

### macOS

```shell
brew install libusb
```

No extra permission setup is normally needed — macOS doesn't gate generic
vendor-class USB devices the way it gates serial ports or camera/mic
access. If `pyusb` still can't open the device, check `system_profiler
SPUSBDataType` to confirm the board enumerates at all before assuming it's
a permissions problem.

### Both: run against the real board

```shell
source .venv/bin/activate
uvicorn backend.app:app --app-dir .
```

The `cube` source is attempted automatically, alongside FlatSat's `serial`
source — both can be plugged in at once, and the mission-select screen
picks which one the dashboard is actively viewing/commanding (see
[`DOCUMENTATION.md`](DOCUMENTATION.md#15-sources-and-switching-between-them-at-runtime)).
Set `PWNSAT_C3_DISABLE_CUBE=1` to skip building this source entirely (e.g.
to let a standalone attack script claim the USB interface without the
dashboard's own reconnect watchdog fighting it for the connection).

---

## 4. RF receive path (optional — GNU Radio / SoapySDR)

Only needed to feed the dashboard from an RTL-SDR or HackRF (the shared
`radio` source, RX only, works for either platform) instead of USB. This is
a separate, system-level install — **not** pip-installable into the
dashboard's own `.venv` — and the bridge script
(`gradio/pwnsat_rx_bridge.py`) runs under this system/Homebrew Python, not
the dashboard's `.venv`.

**Also required for the RF *transmit* side** (the `_rf.py` attack scripts in
the attacks dossier that shell out to `hackrf_transfer` directly, not via
SoapySDR): the `soapysdr-module-hackrf`/`soapyhackrf` packages below are only
the Soapy *driver*, not the `hackrf_transfer`/`hackrf_info` CLI tools — those
come from a separate `hackrf` package, included below.

### Ubuntu

```shell
sudo apt install -y gnuradio gnuradio-dev soapysdr-tools \
  soapysdr-module-rtlsdr soapysdr-module-hackrf hackrf \
  gr-osmosdr cmake build-essential libboost-all-dev

# gr-lora_sdr isn't packaged -- build it from source:
git clone https://github.com/tapparelj/gr-lora_sdr.git
cd gr-lora_sdr
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

### macOS

```shell
brew install gnuradio soapysdr soapyrtlsdr soapyhackrf hackrf cmake

# gr-lora_sdr, same as Ubuntu -- build from source:
git clone https://github.com/tapparelj/gr-lora_sdr.git
cd gr-lora_sdr
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
make install
```

### Both: verify the toolchain before touching the dashboard

```shell
python3 -c "import gnuradio"
python3 -c "import gnuradio.lora_sdr"
python3 -c "import gnuradio.soapy"
python3 -c "import zmq"          # pip install pyzmq if this fails
SoapySDRUtil --find                    # lists every Soapy device it can see
SoapySDRUtil --probe="driver=rtlsdr"   # or driver=hackrf
hackrf_info                            # confirms the hackrf CLI tools are on PATH (TX scripts need this)
```

If Soapy can't see the device, fix the SDR connection/driver before
debugging GNU Radio or the dashboard.

Full receiver usage, signal-path parameters, and capture-saving workflow:
[`gradio/README.md`](gradio/README.md).

---

## Configuration reference

All runtime configuration is environment variables — see
[`DOCUMENTATION.md`](DOCUMENTATION.md#2-configuration-reference-environment-variables)
for the full table (serial port/baud, `PWNSAT_C3_DISABLE_CUBE`, radio ZMQ
address, login credentials, session secret key).

At minimum, before using this anywhere but a local rehearsal, override the
login defaults:

```shell
export PWNSAT_C3_USERNAME=your_operator_name
export PWNSAT_C3_PASSWORD=your_passphrase
export PWNSAT_C3_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

---

## Troubleshooting

- **`ModuleNotFoundError` for anything in `pwnsat_tools/`** — you're not
  running from the repo root, or the `.venv` isn't activated.
  `backend/settings.py` adds `pwnsat_tools/` to `sys.path` at import time,
  but only relative to its own file location — run `uvicorn` from the repo
  root (`--app-dir .` as shown above).
- **Dashboard shows "NO SIGNAL" forever** — check the board is actually
  plugged in and powered; the app retries the transport connection in the
  background instead of crashing, so it can take a few seconds after
  startup for a source to come up.
- **Permission denied opening `/dev/ttyACM0`** (Ubuntu, FlatSat) — you're
  not in the `dialout` group yet, or logged in before adding yourself to
  it. See §2.
- **`usb.core.USBError: [Errno 13] Access denied`** (Ubuntu, PWNCUBE) — the
  udev rule from §3 isn't installed, didn't reload, or the board wasn't
  replugged after adding it.
- **`ImportError: No module named usb` or a libusb backend error** — either
  `pyusb` isn't installed (`pip install -r requirements.txt` again) or
  `libusb` itself is missing (§3's `apt install libusb-1.0-0` /
  `brew install libusb`).
- **PWNCUBE shows as never connecting even though it's plugged in** — the
  board's console may already be claimed by another process (a standalone
  attack script, or a previous C3 instance that didn't shut down cleanly).
  Only one process can hold the USB interface at a time; use `POST
  /api/transport/cube/release` to free it from C3's side, or check for a
  stray Python process still holding it.
- **`gnuradio.lora_sdr` import fails after building `gr-lora_sdr`** — confirm
  you built it against the *same* GNU Radio install `python3 -c "import
  gnuradio"` resolves to (mixing a Homebrew GNU Radio with a
  separately-installed `gr-lora_sdr` build, or vice versa, is the most common
  cause).
- **HackRF: `ValueError: Unsupported sample rate`** — expected if you pass a
  low `--source-samp-rate` explicitly; HackRF's ADC has a 1 MSps floor, see
  [`gradio/README.md`](gradio/README.md#hardware-sample-rate-vs-lora-channel-rate-hackrf).
