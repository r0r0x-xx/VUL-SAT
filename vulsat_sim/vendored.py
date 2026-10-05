"""Pone el toolkit vendored de PWNSAT-C3 en sys.path.

El emulador reusa EXACTAMENTE los mismos bytes que C3 y los PoCs: no se
re-deriva ningún layout SPP/AES/framing aquí.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1] / "PWNSAT-C3" / "pwnsat_tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
