#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-3.0
#
# pwnsat_rx_bridge.py
# Author: r0r0x
#
# Control/CLI script for the SDR-agnostic LoRa downlink receiver
# (pwnsat_lora_rx.PwnsatLoraRX). Replaces the earlier Pluto-only bridge
# (pyPlutoRx.py): the flowgraph's radio source is selected with a
# `--device-args` string (a SoapySDR driver name, via GNU Radio's native
# `gnuradio.soapy` blocks) instead of a Pluto-specific IP/URI, so the same
# script drives either an RTL-SDR or a HackRF.
#
# NOTE: this must run under a Python that has `gnuradio`, `gnuradio.soapy`,
# `gnuradio.lora_sdr`, and `zmq` importable -- e.g. a Homebrew or system
# Python with GNU Radio installed (see INSTALL.md), NOT the PWNSAT-C3
# backend's own .venv. The backend and this bridge are two separate
# processes on purpose (see zmq_link.py).
#
# Examples:
#   python3 pwnsat_rx_bridge.py --device-args rtlsdr
#   python3 pwnsat_rx_bridge.py --device-args hackrf

import argparse
import zmq
import signal
import sys
import string
import time
import struct

import SoapySDR

from pwnsat_lora_rx import PwnsatLoraRX

DEFAULT_PORT = 5005
DEFAULT_DOWNLINK_ADDRESS = "tcp://127.0.0.1:5005"

# Preference order when --device-args isn't given explicitly: RTL-SDR first
# (dedicated receiver, doesn't compete with a HackRF that attack scripts
# need free for TX), HackRF only if that's all there is.
_AUTODETECT_PREFERENCE = ("rtlsdr", "hackrf")


def autodetect_device_args() -> str:
    """Picks a SoapySDR driver name from whatever's actually plugged in,
    instead of a hardcoded default that silently does nothing (or grabs the
    wrong device) when the operator's hardware doesn't match it. Mirrors
    backend/transport/port_detect.py's reasoning for the USB serial side:
    don't make the person setting up this lab hunt down a CLI flag just to
    get RX working."""
    devices = SoapySDR.Device.enumerate()
    # SoapySDRKwargs (not a plain dict) -- dict(d) first for a normal .get().
    available = {dict(d).get("driver") for d in devices if dict(d).get("driver")}
    for driver in _AUTODETECT_PREFERENCE:
        if driver in available:
            return driver
    if available:
        # Something's connected that isn't in our preference list (e.g. a
        # different SDR model) -- use it rather than failing outright.
        return next(iter(available))
    raise RuntimeError(
        "no SDR found for RX -- connect an RTL-SDR or HackRF, or pass "
        "--device-args explicitly for a driver SoapySDR doesn't auto-list"
    )

DOWNLINK_FREQ = 916000000
DOWNLINK_BW = 250000
DOWNLINK_SF = 7

# Generic defaults gr-osmosdr maps onto whatever gain stages the selected
# device actually exposes (RTL-SDR has one tuner gain; HackRF splits this
# into LNA/VGA stages) -- tune per device if reception is weak or clipping.
DEFAULT_RF_GAIN = 30
DEFAULT_IF_GAIN = 20
DEFAULT_BB_GAIN = 20


# PCAP Constants
PCAP_GLOBAL_HEADER_FORMAT = "<LHHIILL"
PCAP_PACKET_HEADER_FORMAT = "<llll"
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_MAX_PACKET_SIZE = 0x0000FFFF

def pcap_header(interface=148):
  return struct.pack(PCAP_GLOBAL_HEADER_FORMAT, PCAP_MAGIC_NUMBER, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, PCAP_MAX_PACKET_SIZE, interface)

class Pcap:
  def __init__(self, packet: bytes, timestamp_seconds: float):
    self.packet = packet
    self.timestamp_seconds = timestamp_seconds
    self.pcap_packet = self.pack()

  def pack(self):
    int_timestamp = int(self.timestamp_seconds)
    timestamp_offset = int((self.timestamp_seconds - int_timestamp) * 1_000_000)
    return struct.pack(PCAP_PACKET_HEADER_FORMAT, int_timestamp, timestamp_offset, len(self.packet), len(self.packet)) + self.packet

  def get(self):
    return self.pcap_packet

def hexdump(data: bytes, width: int = 16) -> str:
  lines = []

  for offset in range(0, len(data), width):
    chunk = data[offset:offset + width]

    # Hexadecimal
    hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
    hex_bytes = hex_bytes.ljust(width * 3)

    # ASCII printable
    ascii_bytes = ''.join(chr(b) if chr(b) in string.printable and b >= 0x20 else '.' for b in chunk)

    lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")

  return "\n".join(lines)

def show_args_config(args):
  print("========== Configuration ==========")
  for k, v in vars(args).items():
    print(f"{k:25}: {v}")
  print("----------------------------------\n")

class Controller:
  def __init__(self, args):
    self.args = args
    self.ctx = None
    self.sock = None
    self.tb = None
    self.running = False
    self.f_output = None
    self.f_pcap_output = None

  def file_write_frame(self, data: bytes):
    if self.f_output is not None:
      ts = time.time_ns()
      length = len(data)
      header = struct.pack("<QH", ts, length)
      self.f_output.write(header)
      self.f_output.write(data)
      self.f_output.flush()

  def file_open(self):
    self.f_output = open(self.args.output_file, "wb")

  def file_close(self):
    if self.f_output:
      self.f_output.close()

  def pcap_write_frame(self, data: bytes):
    if self.f_pcap_output is not None:
      pcap_packet = Pcap(data, time.time()).get()
      self.f_pcap_output.write(pcap_packet)
      self.f_pcap_output.flush()

  def pcap_open(self):
    self.f_pcap_output = open(self.args.pcap_output_file, "wb")
    self.f_pcap_output.write(pcap_header())
    self.f_pcap_output.flush()

  def pcap_close(self):
    if self.f_pcap_output:
      self.f_pcap_output.close()

  def setup(self):
    # device_args (and the other values below) are passed to the constructor
    # rather than set afterwards, because device_args in particular can only
    # take effect at osmosdr.source() construction time -- see the note on
    # PwnsatLoraRX.__init__.
    self.tb = PwnsatLoraRX(
      device_args=str(self.args.device_args),
      frequency=int(self.args.frequency),
      bandwidth=int(self.args.bandwidth),
      zmq_address=self.args.address,
      spread_factor=int(self.args.spread_factor),
      rf_gain=self.args.rf_gain,
      if_gain=self.args.if_gain,
      bb_gain=self.args.bb_gain,
      source_samp_rate=self.args.source_samp_rate,
    )

  def start(self):
    self.running = True
    self.tb.start()
    print("[+] GNU Radio script started")

    self.ctx = zmq.Context()
    self.sock = self.ctx.socket(zmq.SUB)
    self.sock.connect(self.args.address)
    self.sock.setsockopt(zmq.SUBSCRIBE, b"")

    print("[*] Connecting to GNU Radio server")

    if self.args.output_file:
      self.file_open()
    if self.args.pcap_output_file:
      self.pcap_open()

  def stop(self):
    if not self.running:
      return

    print("\n[!] Stooping...")
    if self.tb:
      self.tb.stop()
      self.tb.wait()

    if self.sock:
      self.sock.close(0)

    if self.ctx:
      self.ctx.term()

    self.file_close()
    self.pcap_close()

    print("[*] Clean exit")

  def run(self):
    def handler(sig, frame):
      self.stop()
      sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    self.setup()
    self.start()

    try:
      while True:
        raw_telemetry = self.sock.recv()
        print("\n=========== PACKET ===========")
        print(f"Length: {len(raw_telemetry)}")
        print(hexdump(raw_telemetry))
        self.file_write_frame(raw_telemetry)
        self.pcap_write_frame(raw_telemetry)
    except KeyboardInterrupt:
      self.stop()

def main():
  parser = argparse.ArgumentParser(prog="pwnsat_rx_bridge", description="SDR-agnostic downlink connector for PWNSAT-C3 (RTL-SDR or HackRF)", epilog="r0r0x - 2026")
  parser.add_argument("-f", "--frequency", help="Frequency for Downlink (Hz)", default=DOWNLINK_FREQ)
  parser.add_argument("-bw", "--bandwidth", help="Bandwidth for Downlink (Hz)", default=DOWNLINK_BW)
  parser.add_argument("-sf", "--spread_factor", help="SpreadFactor for Downlink (Hz)", default=DOWNLINK_SF)
  parser.add_argument("-a", "--address", help="ZMQ Address for RX", default=DEFAULT_DOWNLINK_ADDRESS)
  parser.add_argument("-o", "--output-file")
  parser.add_argument("-pcap", "--pcap-output-file")

  parser.add_argument("-d", "--device-args", help="SoapySDR driver name, e.g. 'rtlsdr' or 'hackrf' -- auto-detected from connected hardware if omitted", default=None)
  parser.add_argument("-g", "--rf-gain", type=int, help="Overall/tuner gain (dB)", default=DEFAULT_RF_GAIN)
  parser.add_argument("-ig", "--if-gain", type=int, help="IF gain (dB) -- HackRF's LNA stage", default=DEFAULT_IF_GAIN)
  parser.add_argument("-bg", "--bb-gain", type=int, help="Baseband gain (dB) -- HackRF's VGA stage", default=DEFAULT_BB_GAIN)
  parser.add_argument(
    "-sr", "--source-samp-rate", type=int, default=None,
    help=(
      "Hardware sample rate (Hz). RTL-SDR can sample at the LoRa channel "
      "rate directly (defaults to --bandwidth). HackRF's ADC has a hard "
      "minimum of 1 MSps and cannot sample at 250 kHz directly, so it "
      "defaults to 2000000 automatically when --device-args is 'hackrf'. "
      "Must be an exact integer multiple of --bandwidth."
    ),
  )

  args = parser.parse_args()

  if args.device_args is None:
    args.device_args = autodetect_device_args()
    print(f"[*] --device-args not given -- auto-detected '{args.device_args}'")

  show_args_config(args)

  ctrl = Controller(args)
  ctrl.run()

if __name__ == "__main__":
  main()
