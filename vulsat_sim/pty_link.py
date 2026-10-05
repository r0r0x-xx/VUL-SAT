"""PTY <-> SPP: crea DOS pseudo-terminales sobre el mismo SatelliteCore
(uno para C3, otro para los PoCs de ataque), desenmarca TCs entrantes
(0xAA 0x55 <len:2 BE> <SPP>) de CUALQUIERA de los dos y enmarca TMs
salientes (0xAA <SPP>) difundiéndolas a AMBOS masters.

Publica el nombre de cada slave en un archivo (`.c3_port` / `.sat_port`
por default) para que C3 y los PoCs de ataque lo descubran, cada uno por
su propio puerto -- así C3 queda conectado permanentemente mientras los
ataques corren en el otro extremo, sin release/reconnect.
"""
from __future__ import annotations

import fcntl
import os
import pty
import select
import tty
from pathlib import Path
from typing import Callable

from . import vendored  # noqa: F401

_DEFAULT_C3_PORT_FILE = Path(__file__).resolve().parents[1] / ".c3_port"
_DEFAULT_SAT_PORT_FILE = Path(__file__).resolve().parents[1] / ".sat_port"


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
    """Dos pseudo-terminales (C3 + atacante) que actúan de enlace serie
    entre el satélite emulado y quien se conecte a cada lado master."""

    def __init__(self, on_tc: Callable[[bytes], None],
                 c3_port_file: str | None = None,
                 sat_port_file: str | None = None) -> None:
        self._on_tc = on_tc

        self._c3_master, self._c3_slave = pty.openpty()
        self._sat_master, self._sat_slave = pty.openpty()
        # Modo raw en los slaves (no en los masters): en BSD/macOS el modo
        # canonico/termios vive en el dispositivo slave, y se resetea si
        # se cierran todos sus fds, asi que mantenemos estos fds abiertos
        # para que el consumidor (que abre el slave por nombre) herede
        # el modo raw y reciba los bytes sin buffer de linea.
        tty.setraw(self._c3_slave)
        tty.setraw(self._sat_slave)

        # Masters en modo NO bloqueante: un extremo sin lector (p.ej. el
        # puerto de ataque cuando nadie escucha, o C3 todavía sin levantar)
        # llena su buffer de kernel y, con escritura bloqueante, os.write
        # congelaría TODO el emulador (telemetría y tick incluidos). En no
        # bloqueante, un buffer lleno lanza BlockingIOError y se descarta el
        # frame para ESE puerto, sin frenar al satélite ni al otro extremo.
        for master in (self._c3_master, self._sat_master):
            flags = fcntl.fcntl(master, fcntl.F_GETFL)
            fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self.c3_slave_name = os.ttyname(self._c3_slave)
        self.sat_slave_name = os.ttyname(self._sat_slave)
        # Alias de compatibilidad: código/tests viejos que sólo conocían un
        # puerto (los PoCs/attack) siguen funcionando contra el de ataque.
        self.slave_name = self.sat_slave_name

        self._masters = (self._c3_master, self._sat_master)
        self._bufs = {self._c3_master: b"", self._sat_master: b""}

        self._c3_port_file = Path(c3_port_file) if c3_port_file else _DEFAULT_C3_PORT_FILE
        self._sat_port_file = Path(sat_port_file) if sat_port_file else _DEFAULT_SAT_PORT_FILE
        self._c3_port_file.write_text(self.c3_slave_name + "\n")
        self._sat_port_file.write_text(self.sat_slave_name + "\n")

    def send_tm(self, raw_spp: bytes) -> None:
        """Enmarca y difunde una TM a AMBOS masters (C3 y atacante)."""
        framed = frame_tm(raw_spp)
        for master in self._masters:
            try:
                os.write(master, framed)
            except BlockingIOError:
                pass  # buffer lleno (ese extremo no tiene lector): se descarta
            except OSError:
                pass  # nadie escuchando ahora mismo en ese extremo

    def pump_once(self, timeout: float = 0.2) -> None:
        """Lee de AMBOS masters (lo que haya listo antes de `timeout`),
        desenmarca TCs completos y llama a `on_tc` por cada uno, sin
        importar de cuál de los dos puertos vino."""
        r, _, _ = select.select(list(self._masters), [], [], timeout)
        for master in r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                continue
            if not chunk:
                continue
            self._bufs[master] += chunk
            tcs, self._bufs[master] = deframe_tcs(self._bufs[master])
            for tc in tcs:
                self._on_tc(tc)

    def close(self) -> None:
        for fd in (self._c3_master, self._c3_slave, self._sat_master, self._sat_slave):
            try:
                os.close(fd)
            except OSError:
                pass
        # Los PTY ya murieron: borramos .c3_port/.sat_port para que no
        # queden apuntando a slaves inexistentes (si no, C3/los PoCs se
        # conectarían a un path que ya no existe en la próxima demo).
        for port_file in (self._c3_port_file, self._sat_port_file):
            try:
                port_file.unlink()
            except OSError:
                pass  # ya no existe, nada que hacer
