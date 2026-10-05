"""Runtime configuration and one-time wiring to the telecommand/telemetry
helpers vendored under `PWNSAT-C3/pwnsat_tools/` (copied in from the wider
project so this folder is self-contained and does not reach outside itself
at runtime).

`pwnsat_tools/` is a set of loose scripts, not an installable package. Rather
than duplicate a `sys.path.insert` pattern in every module here, this file
adds it once, at import time, before anything else in the backend imports
from `spp_tools` / `pwnsat_crypto` / `usb_tc_send` / `sim_attack`.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

C3_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = C3_ROOT / "pwnsat_tools"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


# --- serial transport ---
DEFAULT_BAUD = 921600
SERIAL_READ_CHUNK = 4096

# --- link-state watchdog thresholds ---
# Tuned relative to the firmware's own periodic telemetry cadence
# (t_radio_tm_data ~14s, t_radio_nav ~22s, t_radio_sync ~20s, beacon ~18s
# by default in src/worker.cpp) — STALE trips before a normal gap between
# any two of those would, LOST gives real margin before declaring the link
# down outright.
STALE_AFTER_S = 30.0
LOST_AFTER_S = 60.0
HEARTBEAT_INTERVAL_S = 5.0

# A STATUS (0x0C) uptime_s that drops by more than this from the previous
# STATUS frame is treated as a reboot, not clock jitter.
RESET_UPTIME_TOLERANCE_S = 2

# --- link watchdog initial assumption ---
# The full firmware (secure_link enabled by default) sends a STATUS (0x0C)
# frame that corrects this soon after connecting, so defaulting to True is
# safe there. Firmware builds without secure_link.cpp (e.g. plain upstream,
# or intermediate feature-bisection builds) never send that correcting
# frame, so the bus would try to AES-decrypt plaintext forever -- override
# with PWNSAT_C3_ASSUME_ENCRYPTED=0 when testing against those.
ASSUME_SECURE_LINK_ENABLED = os.environ.get("PWNSAT_C3_ASSUME_ENCRYPTED", "1") != "0"

# --- default AES / ground-station constants (mirrors usb_tc_send.py) ---
DEFAULT_FLASH_WINDOW_ID = 0xA5
DEFAULT_FLASH_UNLOCK_TAG = 0xC35A
DEFAULT_GS_AUTH_KEY = 0xC0DEFACE

# --- dashboard login ---
# Demo defaults -- override via environment variables for anything other than
# local rehearsal. SESSION_SECRET_KEY signs the session cookie; a random key
# is generated per process start if none is set, which means sessions do not
# survive a restart unless a fixed key is provided.
LOGIN_USERNAME = os.environ.get("PWNSAT_C3_USERNAME", "operator")
LOGIN_PASSWORD = os.environ.get("PWNSAT_C3_PASSWORD", "pwnsat")
SESSION_SECRET_KEY = os.environ.get("PWNSAT_C3_SECRET_KEY", secrets.token_hex(32))
