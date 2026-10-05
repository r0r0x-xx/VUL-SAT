"""PTY <-> SPP: crea un pseudo-terminal, desenmarca TCs entrantes
(0xAA 0x55 <len:2 BE> <SPP>) y enmarca TMs salientes (0xAA <SPP>).
Publica el nombre del slave en un archivo (default .sat_port) para que
C3 y los PoCs de ataque lo descubran.
"""
from __future__ import annotations

import os
import pty
import select
import tty
from pathlib import Path
from typing import Callable

from . import vendored  # noqa: F401

_DEFAULT_PORT_FILE = Path(__file__).resolve().parents[1] / ".sat_port"


def frame_tm(raw_spp: bytes) -> bytes:
    """Enmarca una TM saliente con el byte de sincronismo 0xAA."""
    return b"\xAA" + raw_spp


def deframe_tcs(buf: bytes) -> tuple:
    """Extrae TCs completos (0xAA 0x55 <len:2 BE> <SPP>) de `buf`.

    Devuelve (lista_de_SPP, resto_sin_consumir). Si hay basura antes de
    un sync valido, se descarta (resincroniza); si el ultimo frame esta
    incompleto, se conserva en el resto a la espera de mas bytes.
    """
    tcs = []
    i = 0
    n = len(buf)
    while True:
        j = buf.find(b"\xAA\x55", i)
        if j < 0:
            i = n
            break
        if j + 4 > n:
            i = j  # header incompleto -> esperar mas bytes desde el sync
            break
        length = int.from_bytes(buf[j + 2:j + 4], "big")
        end = j + 4 + length
        if end > n:
            i = j  # payload incompleto -> esperar mas bytes desde el sync
            break
        tcs.append(buf[j + 4:end])
        i = end
    return tcs, buf[i:]


class PtyLink:
    """Pseudo-terminal que actua de enlace serie entre el satelite emulado
    y quien se conecte al lado master (C3, PoCs de ataque)."""

    def __init__(self, on_tc: Callable[[bytes], None],
                 port_file: str | None = None) -> None:
        self._on_tc = on_tc
        self._master, self._slave = pty.openpty()
        # Modo raw en el slave (no en el master): en BSD/macOS el modo
        # canonico/termios vive en el dispositivo slave, y se resetea si
        # se cierran todos sus fds, asi que mantenemos este fd abierto
        # para que el consumidor (que abre el slave por nombre) herede
        # el modo raw y reciba los bytes sin buffer de linea.
        tty.setraw(self._slave)
        self.slave_name = os.ttyname(self._slave)
        self._buf = b""
        self._port_file = Path(port_file) if port_file else _DEFAULT_PORT_FILE
        self._port_file.write_text(self.slave_name + "\n")

    def send_tm(self, raw_spp: bytes) -> None:
        """Enmarca y escribe una TM al master del PTY."""
        try:
            os.write(self._master, frame_tm(raw_spp))
        except OSError:
            pass  # nadie escuchando ahora mismo

    def pump_once(self, timeout: float = 0.2) -> None:
        """Lee del master (si hay datos antes de `timeout`), desenmarca
        TCs completos y llama a `on_tc` por cada uno."""
        r, _, _ = select.select([self._master], [], [], timeout)
        if not r:
            return
        try:
            chunk = os.read(self._master, 4096)
        except OSError:
            return
        if not chunk:
            return
        self._buf += chunk
        tcs, self._buf = deframe_tcs(self._buf)
        for tc in tcs:
            self._on_tc(tc)

    def close(self) -> None:
        try:
            os.close(self._master)
        except OSError:
            pass
        try:
            os.close(self._slave)
        except OSError:
            pass
        # El PTY ya murió: borramos .sat_port para que no quede apuntando
        # a un slave inexistente (si no, C3/los PoCs se conectarían a un
        # path que ya no existe en la próxima demo).
        try:
            self._port_file.unlink()
        except OSError:
            pass  # ya no existe, nada que hacer
