"""
Shim de compatibilidad macOS para pyserial + PTY.

En macOS, pyserial intenta fijar el baudrate exacto vía el ioctl IOSSIOSPEED
cuando el valor no es uno de los "standard" (ej. 921600). El driver de PTY del
kernel no soporta ese ioctl, así que `serial.Serial(port, 921600)` falla con
`[Errno 25] Inappropriate ioctl for device` al abrir un pseudo-terminal.

En un PTY el baudrate es puramente cosmético: no hay línea serie física, los
bytes simplemente pasan por el buffer del pty sin importar a qué velocidad se
"configuró". Por eso, si el puerto que se abre es un PTY (no hardware real),
podemos bajar el baud pedido a uno estándar soportado (115200) sin que el
comportamiento cambie en absoluto para quien consume el puerto.

Este módulo se auto-importa al arrancar el intérprete cuando su directorio
está en PYTHONPATH (mecanismo estándar `sitecustomize`). Debe ser:
  - Seguro de importar aunque pyserial no esté instalado.
  - Idempotente (no debe parchear dos veces si se importa más de una vez).
  - Inocuo para hardware real: solo actúa sobre PTYs.
"""

import os


def _es_pty(port_name):
    """True si `port_name` parece un pseudo-terminal (PTY), no hardware real.

    macOS: los PTYs del lado esclavo se llaman /dev/ttys000, /dev/ttys001, etc.
    (basename empieza con "ttys"). El hardware real usa prefijos distintos,
    por ejemplo /dev/tty.usbmodemXXXX o /dev/tty.usbserial-XXXX (basename
    empieza con "tty." no "ttys").
    Linux: los PTYs viven en /dev/pts/N.
    Linux hardware real: /dev/ttyUSB0, /dev/ttyACM0 (basename empieza con
    "ttyUSB"/"ttyACM", no con "ttys").
    """
    if not isinstance(port_name, str) or not port_name:
        return False
    if port_name.startswith("/dev/pts/"):
        return True
    base = os.path.basename(port_name)
    return base.startswith("ttys")


def _aplicar_parche():
    try:
        import serial
    except ImportError:
        # pyserial no está instalado: nada que parchear.
        return

    if getattr(serial.Serial, "_ptycompat_parcheado", False):
        # Ya parcheado (ej. sitecustomize importado más de una vez): no
        # volver a envolver _reconfigure_port para evitar doble-wrap.
        return

    _original_reconfigure_port = serial.Serial._reconfigure_port

    def _reconfigure_port_parcheado(self, *args, **kwargs):
        try:
            nombre_puerto = getattr(self, "port", "") or ""
            baud_actual = getattr(self, "_baudrate", 0)
            if _es_pty(nombre_puerto) and baud_actual > 230400:
                # En un PTY el baud es cosmético: lo bajamos a un valor
                # estándar que el driver de pty sí acepta (115200), sin
                # afectar los bytes que realmente se transmiten.
                self._baudrate = 115200
        except Exception:
            # Nunca dejamos que el shim rompa la apertura real del puerto.
            pass
        return _original_reconfigure_port(self, *args, **kwargs)

    serial.Serial._reconfigure_port = _reconfigure_port_parcheado
    serial.Serial._ptycompat_parcheado = True


_aplicar_parche()
