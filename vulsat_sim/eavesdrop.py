"""PoC 01 (eavesdropping) sobre USB: lectura PASIVA del enlace serie del
satélite emulado. No transmite nada -- sólo abre el puerto, desenmarca la
telemetría (satélite -> tierra, sync 0xAA desnudo, sin el 0x55 de los TCs)
y decodifica cada SPP, igual que haría un atacante escuchando el bus USB
real.

Reutiliza el mismo toolkit vendored que el resto del emulador y los PoCs:
`iter_usb_sync_packets` (usb_tc_send.py) para el framing y `decode_packet`
/ `decrypt_payload` para el contenido -- no se re-deriva ningún byte acá.
"""
from __future__ import annotations

import argparse
import os
import select
import sys
import time

from . import vendored  # noqa: F401

from spp_tools import decode_packet
from pwnsat_crypto import decrypt_payload
from usb_tc_send import iter_usb_sync_packets

DEFAULT_BAUD = 921600


def describe_tm(raw_spp: bytes, aes_enabled: bool = True) -> str:
    """Decodifica un SPP crudo y arma la línea de log para eavesdrop.

    Función pura (sin I/O) para poder testear el deframe/decode sin un
    puerto real. Intenta desencriptar el payload si `aes_enabled`; si no
    parece encriptado (o la desencripción falla) cae de vuelta al payload
    crudo.
    """
    try:
        pkt = decode_packet(raw_spp)
    except ValueError as exc:
        return f"[eavesdrop] SPP inválido ({exc}): {raw_spp.hex()}"

    header = (f"[eavesdrop] {pkt.packet_type_name} APID=0x{pkt.apid:03X} "
              f"({pkt.apid_name}) seq={pkt.sequence_count}")

    if not pkt.data:
        return f"{header} payload=<vacío>"

    if aes_enabled:
        try:
            plain = decrypt_payload(pkt.data)
            return f"{header} payload(AES->plano)={plain.hex()}"
        except ValueError:
            pass  # no era un bloque AES válido -- cae a crudo

    return f"{header} payload(crudo)={pkt.data.hex()}"


class _RawFdReader:
    """Lector mínimo sobre un fd crudo (os.open), con la misma interfaz
    .read(n)/.close() que usamos de serial.Serial. Fallback para cuando el
    puerto es un PTY (el emulador): un PTY no tiene velocidad real, y en
    macOS pyserial puede fallar al intentar fijar un baudrate no estándar
    (921600) vía ioctl sobre un pseudo-terminal."""

    def __init__(self, path: str) -> None:
        self._fd = os.open(path, os.O_RDONLY | os.O_NOCTTY)

    def read(self, n: int) -> bytes:
        r, _, _ = select.select([self._fd], [], [], 0.2)
        if not r:
            return b""
        try:
            return os.read(self._fd, n)
        except OSError:
            return b""

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


def _open_reader(port: str, baud: int):
    import serial  # import diferido: no hace falta pyserial para testear describe_tm
    try:
        return serial.Serial(port, baud, timeout=0.2)
    except (OSError, ValueError):
        # Puerto real sin ese baudrate, o (más común acá) un PTY: pyserial
        # no siempre puede fijar un baudrate no estándar en un pseudo-tty.
        # El PTY del emulador no tiene velocidad real -- leer el fd crudo
        # alcanza.
        return _RawFdReader(port)


def run(port: str, seconds: float | None = None, baud: int = DEFAULT_BAUD,
        aes_enabled: bool = True) -> None:
    print(f"[eavesdrop] escuchando (solo lectura) {port} @ {baud} baud -- Ctrl-C para salir")
    ser = _open_reader(port, baud)
    buf = b""
    t0 = time.monotonic()
    try:
        while seconds is None or (time.monotonic() - t0) < seconds:
            chunk = ser.read(4096)
            if not chunk:
                continue
            buf += chunk
            packets, buf = iter_usb_sync_packets(buf)
            for raw in packets:
                print(describe_tm(raw, aes_enabled=aes_enabled))
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()
        print("[eavesdrop] fin.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="PoC 01 -- eavesdropping pasivo del USBRadioLink")
    parser.add_argument("--port", required=True,
                         help="puerto serie del PTY/USBRadioLink")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--seconds", type=float, default=None,
                         help="cortar automáticamente tras N segundos (default: Ctrl-C)")
    parser.add_argument("--no-decrypt", action="store_true",
                         help="no intentar AES-decrypt del payload")
    args = parser.parse_args(argv)
    run(args.port, seconds=args.seconds, baud=args.baud,
        aes_enabled=not args.no_decrypt)


if __name__ == "__main__":
    sys.exit(main())
