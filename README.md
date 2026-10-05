# VUL-SAT

## 1. Qué es

VUL-SAT es un laboratorio de satélite **vulnerable-by-design**: un emulador
100% software de un FlatSat (sin hardware, sin RF) que se conecta a la
ground station **PWNSAT-C3** y a 4 PoCs de ataque, todo a través de un puerto
serie virtual (PTY) local.

Componentes:

- **Emulador FlatSat (VUL-SAT)** — firmware simulado en memoria: estado
  orbital, thrusters, beacon, modo AES, telemetría periódica.
- **PWNSAT-C3** — dashboard web de ground station (login, panel de control,
  telemetría en vivo).
- **PoCs de ataque** (`attacks/00`–`03`):
  - `00` recon — enumeración de APIDs del bus.
  - `01` eavesdropping — lectura pasiva de telemetría cifrada.
  - `02` fuzzing/crash — payload malformado que tumba el satélite.
  - `03` command injection — inyección de comandos sin autenticación.

Todo el tráfico es interno, por un PTY: no hay radio ni hardware real
involucrado.

## 2. Prerrequisitos

- Ubuntu (arm64 o amd64) o macOS.
- `git`.
- Python 3.11 o superior, con `venv`.

En Ubuntu, si falta algo:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
```

## 3. Instalación desde cero

```bash
git clone https://github.com/r0r0x-xx/VUL-SAT
cd VUL-SAT
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4. Arquitectura (resumen)

El emulador abre **dos** PTY sobre el mismo satélite emulado (mismo
`SatelliteCore`, mismo estado) y publica cada extremo esclavo en un
archivo: `.c3_port` para la ground station y `.sat_port` para los PoCs de
ataque. PWNSAT-C3 y los PoCs leen el archivo que les corresponde y abren
ese PTY como si fuera un puerto serie real, hablando el protocolo SPP (con
AES opcional) que define `PWNSAT-C3/pwnsat_tools`. El emulador, C3 y los
PoCs comparten exactamente ese mismo toolkit vendored: nadie re-deriva el
framing.

La telemetría se difunde a **ambos** puertos y los telecomandos de
**cualquiera** de los dos se procesan contra el mismo estado: C3 queda
conectado todo el tiempo mientras los PoCs atacan por el otro puerto, sin
necesidad de soltar/retomar el serial.

```
                      <--PTY (.c3_port)-->  PWNSAT-C3 (dashboard)
vulsat_sim (FlatSat)
                      <--PTY (.sat_port)--> attacks/00..03 (PoCs)
```

El emulador también simula GPS: el satélite arranca sobre **Cartago,
Costa Rica** y su traza terrestre avanza con el tiempo; la ground station
(GS_STATUS) está fija en **Ciudad de México**, con la distancia real
(haversine) entre ambos puntos.

## 5. Ejecución paso a paso (3 terminales)

**Terminal 1 — satélite emulado:**

```bash
./vulsat sat
```

Levanta el FlatSat con una TUI de órbita (y posición GPS) en vivo, y
publica los dos PTY en `.c3_port` y `.sat_port`. Dejá esta terminal
visible durante toda la demo.

**Terminal 2 — ground station:**

```bash
./vulsat c3
```

Arranca PWNSAT-C3 apuntado al puerto del emulador. Abrí
`http://127.0.0.1:8000`, iniciá sesión con `operator` / `pwnsat` y elegí el
FlatSat en el dashboard.

**Terminal 3 — ataques:**

Gracias al doble PTY, C3 no necesita soltar el puerto: los PoCs atacan por
`.sat_port` mientras C3 sigue conectado por `.c3_port`.

```bash
./vulsat login                   # autentica y guarda la cookie de sesión
./vulsat attack 00               # recon: enumera APIDs válidos del bus
./vulsat attack 01               # eavesdrop: telemetría descifrada en vivo
./vulsat attack 02               # fuzzing: crash del satélite + reboot automático
./vulsat attack 03 --power 255   # inyección de comando: thruster a 255 sin auth
```

Qué observar en cada PoC:

- **00 (recon):** lista los APIDs que responden en el bus, sin necesitar
  credenciales ni conocer el protocolo de antemano.
- **01 (eavesdrop):** muestra la telemetría del satélite descifrada en texto
  plano, pese a viajar cifrada por el enlace.
- **02 (fuzzing/crash):** el satélite cae — se ve tanto en la TUI del
  emulador (`CRASH`) como en el dashboard de C3 (enlace caído), y se
  recupera solo tras unos segundos (auto-reboot de la demo).
- **03 (command injection):** `./vulsat attack 03 --power 255` fija el
  thruster a 255 sin pasar por ninguna autenticación — se ve reflejado de
  inmediato en la TUI y en C3.

## 6. Tests

```bash
python3 -m pytest
```

## 7. Notas de compatibilidad / troubleshooting

- **PTY a 921600 baud (macOS y Linux):** pyserial intenta fijar el baudrate
  exacto solicitado por C3 y los PoCs (921600) usando mecanismos que los
  drivers de pseudo-terminal no soportan (en macOS, el ioctl
  `IOSSIOSPEED`). Como en un PTY el baudrate es cosmético —no hay línea
  física—, `vulsat_sim/ptycompat/sitecustomize.py` parchea pyserial para
  clampear el baud a 115200 **solo cuando el puerto abierto es un PTY**
  (`/dev/ttys*` en macOS, `/dev/pts/*` en Linux). El launcher `./vulsat`
  inyecta ese shim vía `PYTHONPATH` al correr `c3` y `attack`. El hardware
  real (`/dev/tty.usbmodem*`, `/dev/ttyUSB*`, `/dev/ttyACM*`) nunca se ve
  afectado: ahí sigue aplicando 921600 sin cambios.
- **`python3` vs `python`:** Ubuntu suele no tener el alias `python`; por
  eso `./vulsat` usa siempre `python3` (configurable con la variable de
  entorno `PYTHON`).
- **`PWNSAT-C3/` y `attacks/` no se modifican:** son copias vendored,
  byte-idénticas a su origen; todo el soporte de compatibilidad vive fuera
  de esos directorios.
