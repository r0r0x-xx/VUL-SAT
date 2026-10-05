"""
Tests del shim vulsat_sim/ptycompat/sitecustomize.py.

Importamos el módulo explícitamente por su ruta (no dependemos de que
PYTHONPATH dispare el auto-import de sitecustomize dentro de pytest).
"""

import importlib.util
import os
import pty
import sys

import pytest
import serial

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM_PATH = os.path.join(ROOT, "vulsat_sim", "ptycompat", "sitecustomize.py")


def _cargar_shim():
    spec = importlib.util.spec_from_file_location("tec_ptycompat_shim", SHIM_PATH)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="module")
def shim():
    return _cargar_shim()


def test_predicado_pty_macos(shim):
    assert shim._es_pty("/dev/ttys003") is True
    assert shim._es_pty("/dev/ttys0") is True


def test_predicado_pty_linux(shim):
    assert shim._es_pty("/dev/pts/4") is True


def test_predicado_hardware_real_no_es_pty(shim):
    # Hardware real: NO debe tocarse, para que 921600 siga aplicando tal cual.
    assert shim._es_pty("/dev/tty.usbmodem14101") is False
    assert shim._es_pty("/dev/tty.usbserial-A1B2C3") is False
    assert shim._es_pty("/dev/ttyUSB0") is False
    assert shim._es_pty("/dev/ttyACM0") is False
    assert shim._es_pty("") is False
    assert shim._es_pty(None) is False


def test_abrir_pty_real_a_921600_funciona_con_el_shim(shim):
    """Prueba empírica del defecto y de la corrección.

    Sin el shim, `serial.Serial(nombre_esclavo_pty, 921600)` falla en macOS
    con [Errno 25] Inappropriate ioctl for device. Con el shim aplicado,
    el baud se clampea a 115200 internamente para el PTY y la apertura
    tiene éxito.
    """
    maestro_fd, esclavo_fd = pty.openpty()
    nombre_esclavo = os.ttyname(esclavo_fd)
    os.close(esclavo_fd)
    try:
        puerto = serial.Serial(nombre_esclavo, 921600, timeout=0.1)
        try:
            assert puerto.is_open
            # El shim clampeó el baud real a uno soportado por el pty.
            assert puerto.baudrate <= 230400
        finally:
            puerto.close()
    finally:
        os.close(maestro_fd)


def test_puerto_no_pty_no_se_toca_por_el_predicado(shim):
    # No abrimos hardware real en CI, pero el predicado de nombre debe dejar
    # pasar esos puertos sin marcarlos como PTY (verificado arriba) y por lo
    # tanto `_reconfigure_port_parcheado` nunca tocaría su baudrate.
    assert shim._es_pty("/dev/tty.usbmodem14101") is False
