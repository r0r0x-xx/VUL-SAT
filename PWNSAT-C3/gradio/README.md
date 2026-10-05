# GNU Radio LoRa Receiver

This folder contains the PWNSAT-C3 passive LoRa downlink receiver workflow for GNU Radio, usable with either an RTL-SDR (recommended dedicated receiver) or a HackRF, via GNU Radio's native `gnuradio.soapy` blocks (SoapySDR).

Use it only against a Pwnsat board, lab transmitter, replay source, or signal source you own or are explicitly authorized to monitor. The receiver is passive, but local law and lab rules still apply.

## Files

| File | Purpose |
| --- | --- |
| `pwnsat_lora_rx.grc` | GNU Radio Companion source flowgraph. Edit this when changing the receiver design. |
| `pwnsat_lora_rx.py` | Python top block. Connects a Soapy source (RTL-SDR or HackRF, selected by `device_args`) through a decimating band-pass filter into the LoRa receiver, and publishes decoded bytes over ZeroMQ. |
| `pwnsat_rx_bridge.py` | Control script. It configures the top block, starts GNU Radio, subscribes to the ZeroMQ byte stream, prints decoded packet hexdumps, and can write raw captures or PCAP output. Also what `backend/transport/zmq_link.py` expects to be running when the dashboard is started with `PWNSAT_C3_TRANSPORT=radio`. |

## Signal Path

```text
RTL-SDR or HackRF
  -> gnuradio.soapy source (device_args: "rtlsdr" or "hackrf")
  -> freq_xlating_fir_filter_ccc (decimates hardware rate down to the LoRa channel rate)
  -> GNU Radio LoRa receiver (gnuradio.lora_sdr)
  -> ZeroMQ PUB socket
  -> pwnsat_rx_bridge.py SUB socket (or backend/transport/zmq_link.py, if feeding the dashboard)
  -> terminal hexdump, raw file, PCAP file, or the PWNSAT-C3 dashboard
```

The default receiver parameters match the current Pwnsat downlink lab profile:

| Parameter | Default |
| --- | --- |
| Center frequency | `916000000` Hz |
| LoRa channel bandwidth | `250000` Hz |
| Hardware sample rate | RTL-SDR: `250000` Hz (= bandwidth, sampled directly). HackRF: `2000000` Hz (see below — HackRF cannot sample at 250 kHz directly). |
| Spreading factor | `7` |
| Coding rate | Firmware `CR5`, equivalent to LoRa 4/5; represented as `cr=1` in the GNU Radio LoRa block |
| Sync word | `0x12` |
| CRC | Enabled in the generated LoRa receiver block |
| Device args | `rtlsdr` (swap to `hackrf` to receive on a HackRF instead) |
| RF / IF / BB gain | `30` / `20` / `20` dB |
| ZeroMQ output | `tcp://127.0.0.1:5005` |

### Hardware sample rate vs. LoRa channel rate (HackRF)

RTL-SDR can sample directly at the LoRa channel rate. **HackRF's ADC has a
hard minimum of 1 MSps** and rejects any lower rate outright
(`ValueError: Unsupported sample rate (250000.000000). Rate must be in the
range 1000000.000000, ..., 20000000.000000`). To use a HackRF, the flowgraph
samples at a higher `source_samp_rate` (2,000,000 Hz by default, chosen
automatically whenever `--device-args hackrf` and no `-sr` override is given)
and then digitally decimates down to the 250 kHz LoRa channel with a
`freq_xlating_fir_filter_ccc` (`decim = source_samp_rate // bandwidth`, so 8
at the defaults). `source_samp_rate` must always be an exact integer multiple
of `bandwidth`; override it with `-sr/--source-samp-rate` if you change
`--bandwidth` or want a different decimation ratio.

### Gain stage naming

RTL-SDR exposes a single tuner gain, tried first for `--rf-gain`. HackRF
splits gain into separate LNA and VGA stages instead — the flowgraph tries
Soapy gain names `IF`/`LNA` for `--if-gain` and `BB`/`VGA` for `--bb-gain`, in
that order, so the same three CLI flags (`--rf-gain`/`--if-gain`/`--bb-gain`)
work unmodified on either device without you needing to know SoapySDR's
per-driver gain-element names.

Gain, like frequency and bandwidth, is a CLI flag on `pwnsat_rx_bridge.py` -- no need to edit `pwnsat_lora_rx.py` or the `.grc` just to retune gain per device.

`--device-args` (device selection) is the one parameter that can *only* be set at flowgraph construction time -- Soapy opens the physical device once, at startup, and can't be repointed at different hardware afterwards. `pwnsat_rx_bridge.py` already handles this correctly (it passes `--device-args` into the `PwnsatLoraRX` constructor); if you drive `pwnsat_lora_rx.PwnsatLoraRX` directly instead of through the bridge script, pass `device_args=` to its constructor.

## Requirements

Install and verify these before running the receiver:

- GNU Radio 3.10 compatible with the generated flowgraph.
- `soapysdr` plus the backend driver for whichever device you use (`soapysdr-module-rtlsdr` for RTL-SDR, `soapysdr-module-hackrf` for HackRF). On macOS/Homebrew: `brew install gnuradio soapysdr soapyrtlsdr soapyhackrf`.
- `gr-lora_sdr` (built from source: https://github.com/tapparelj/gr-lora_sdr) providing `gnuradio.lora_sdr`.
- Python `pyzmq`.
- The SDR reachable over USB.

Quick checks:

```shell
python3 -c "import gnuradio"
python3 -c "import gnuradio.lora_sdr"
python3 -c "import gnuradio.soapy"
python3 -c "import zmq"
SoapySDRUtil --find                 # lists every Soapy device it can see
SoapySDRUtil --probe="driver=rtlsdr"   # or driver=hackrf -- confirms Soapy can open the device
```

If Soapy can't see the device, fix the SDR connection/driver before debugging GNU Radio.

Note: `pwnsat_rx_bridge.py` needs to run under whichever Python actually has `gnuradio`/`gnuradio.soapy`/`gnuradio.lora_sdr` importable (e.g. a Homebrew or system Python with GNU Radio installed -- see `INSTALL.md`), not the PWNSAT-C3 backend's own `.venv` -- see the docstring in `backend/transport/zmq_link.py`.

## Running the Receiver

From `PWNSAT-C3/`:

```shell
python3 gradio/pwnsat_rx_bridge.py
```

Equivalent explicit command (RTL-SDR):

```shell
python3 gradio/pwnsat_rx_bridge.py \
  --device-args rtlsdr \
  --frequency 916000000 \
  --bandwidth 250000 \
  --address tcp://127.0.0.1:5005
```

Or with a HackRF instead (source sample rate defaults to 2 MSps automatically):

```shell
python3 gradio/pwnsat_rx_bridge.py --device-args hackrf
```

Explicit HackRF command with a non-default source sample rate:

```shell
python3 gradio/pwnsat_rx_bridge.py \
  --device-args hackrf \
  --frequency 916000000 \
  --bandwidth 250000 \
  --source-samp-rate 4000000
```

The control script prints its configuration, starts the generated GNU Radio top block, subscribes to the ZeroMQ packet stream, and prints each decoded LoRa payload as a hexdump.

Stop it with `Ctrl-C`.

## Feeding the PWNSAT-C3 Dashboard

Start the bridge first (it must be running before the dashboard connects):

```shell
python3 gradio/pwnsat_rx_bridge.py --device-args hackrf
```

Then, in a separate terminal, start the dashboard against the radio transport:

```shell
PWNSAT_C3_TRANSPORT=radio PWNSAT_C3_ZMQ_ADDRESS=tcp://127.0.0.1:5005 \
    uvicorn backend.app:app --app-dir .
```

`/api/status` will report `"transport": "radio (RX only) via tcp://127.0.0.1:5005"` and `"supports_tx": false` once connected -- the dashboard receives and decodes every downlink packet exactly like it does over USB, but the Operations/Attack panels grey out since there is no uplink flowgraph to send commands through yet.

## Saving Captures

Write length-prefixed raw frames:

```shell
python3 gradio/pwnsat_rx_bridge.py -o captures/pwnsat_lora_frames.bin
```

Each raw frame is stored as:

```text
uint64 little-endian timestamp_ns
uint16 little-endian frame_length
frame bytes
```

Write a PCAP file:

```shell
python3 gradio/pwnsat_rx_bridge.py -pcap captures/pwnsat_lora_downlink.pcap
```

The PCAP writer stores each decoded LoRa payload as a packet record. Use it as a convenient packet-review artifact, not as proof that Wireshark understands every Pwnsat field automatically.

Create the capture directory first if needed:

```shell
mkdir -p captures
```

## Intercepting Pwnsat LoRa Information

Use this workflow for passive downlink interception:

1. Confirm you are in an authorized lab setup and that the target is the Pwnsat downlink or a replay source.
2. Connect the RTL-SDR (or HackRF) and verify Soapy can see it (`SoapySDRUtil --find`).
3. Confirm the expected downlink parameters in the firmware and lab notes.
4. Start the receiver with the matching frequency and bandwidth.
5. Trigger safe board traffic such as PING, firmware-version request, normal telemetry, beacon, or flash transfer.
6. Watch the terminal for `PACKET` sections and hexdumps.
7. Save raw or PCAP output for later analysis.
8. Decode captured payloads as SPP with `pwnsat_tools/spp_tools.py` when the payload begins with a valid SPP primary header.

Example passive capture:

```shell
mkdir -p captures
python3 gradio/pwnsat_rx_bridge.py \
  --frequency 916000000 \
  --bandwidth 250000 \
  --device-args rtlsdr \
  --output-file captures/pwnsat_lora_frames.bin \
  --pcap-output-file captures/pwnsat_lora_downlink.pcap
```

In another terminal, send a known-safe command to the board through USB:

```shell
python3 pwnsat_tools/usb_tc_send.py --port /dev/cu.usbmodemfsat3 --command ping
python3 pwnsat_tools/usb_tc_send.py --port /dev/cu.usbmodemfsat3 --command fw
```

The receiver should show the corresponding downlink payloads when the SDR is tuned correctly and the signal quality is sufficient.

## Decoding Captured SPP Bytes

When the printed payload begins with a recognizable SPP primary header, copy the hex bytes and decode them with the local helper:

```shell
python3 - <<'PY'
from pwnsat_tools.spp_tools import print_packet

raw = bytes.fromhex("0001c00100040141434b00")
print_packet(raw)
PY
```

For longer captures, write a small parser for the raw frame format or inspect the PCAP records and feed each LoRa payload into `pwnsat_tools/spp_tools.py`.

## Regenerating the GNU Radio Script

If you edit `pwnsat_lora_rx.grc`, regenerate the Python top block from GNU Radio Companion and keep the generated file next to the `.grc` file:

```shell
gnuradio-companion gradio/pwnsat_lora_rx.grc
```

Open the flowgraph, verify the block parameters, and generate the Python file. After regeneration, rerun `pwnsat_rx_bridge.py` and confirm that packets still appear on the configured ZeroMQ address.

## Notes and Limitations

- The flowgraph is configured for the current lab profile. If the board firmware or radio configuration changes, update frequency, bandwidth, spreading factor, coding rate, sync word, and CRC expectations together.
- RTL-SDR's tuner crystal drifts more than a lab-grade SDR's TCXO. On a narrowband 250 kHz signal that drift can walk the center frequency off the channel; calibrate the PPM offset first (`rtl_test -p` or `kalibrate-rtl`) if reception is unreliable.
- The control script exposes `--spread_factor`, but the current generated top block is built around the default spreading factor. Treat SF changes as a flowgraph setting to verify in GNU Radio Companion.
- Poor gain, wrong antenna, wrong frequency, wrong bandwidth, or wrong sync word can all look like "no packets."
- **Known open issue:** no downlink signal has been observed over the air yet on the lab FlatSat, tested with both an RTL-SDR and a HackRF at multiple gains and frequencies around 916 MHz. Both SDRs show an identical null result (flat noise floor, no bursts), which rules out a receiver-specific problem. Leading hypothesis is a firmware-side TX power gap on the downlink radio (`src/rdownlink.cpp` never calls `setOutputPower()`, defaulting to RadioLib's stock 10dBm vs. the uplink radio's explicit 22dBm) -- unconfirmed, and not yet fixed pending sign-off on the firmware change.
- This workflow intercepts cleartext lab LoRa payloads. It does not bypass encryption or authorization controls.
