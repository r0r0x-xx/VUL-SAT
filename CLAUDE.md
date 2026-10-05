# CLAUDE.md — VUL-SAT

Guía de contexto para sesiones de Claude Code sobre este proyecto. Idioma de trabajo: **español**.
Repo: **https://github.com/r0r0x-xx/VUL-SAT** (privado). Rama principal: `main`.

## Qué es

**VUL-SAT** es un laboratorio de satélite vulnerable-by-design, **100% software** (sin hardware, sin RF),
para charlas/formación en ciberseguridad aeroespacial. Tiene tres piezas:

1. **Emulador de FlatSat** (`vulsat_sim/`): "firmware" emulado de un satélite con estado vivo (órbita/GPS,
   thrusters, modo de misión, sensores, enlace AES) y una TUI de órbita. Habla por puertos serie virtuales (PTY).
2. **PWNSAT-C3** (`PWNSAT-C3/`, **vendored, no editar**): la ground station / dashboard web (FastAPI) real del
   ecosistema PWNSAT. Se conecta al emulador como si fuera hardware USB y decodifica la telemetría en paneles.
3. **PoCs de ataque 00–03** (`attacks/`, **vendored, no editar**): recon/enum APID (00), eavesdrop (01),
   fuzzing/crash por integer-underflow (02), command injection de thruster sin auth (03).

Todo es interno: el emulador expone dos PTY y C3 + los ataques se conectan a ellos; no hay release/reconnect.

## Reglas de oro (NO romper)

- **Nunca editar `PWNSAT-C3/` ni `attacks/`** (son copias byte-idénticas del upstream PWNSAT). Verificar con
  `git status --short -- PWNSAT-C3 attacks` (debe quedar vacío). Toda adaptación se hace del lado del emulador
  o del launcher (p.ej. inyectando `PYTHONPATH`/env), nunca tocando esos archivos.
- **Reusar el toolkit vendored** para todos los bytes del protocolo, no re-derivar: `spp_tools`
  (`build_tc/build_tm/decode_packet`), `pwnsat_crypto` (`encrypt_payload/decrypt_payload`,
  `AES_KEY=b"PWNsatLabKey1234"`), `usb_tc_send` (`frame_usb`, `iter_usb_sync_packets`). Se importan vía
  `vulsat_sim/vendored.py` (pone `PWNSAT-C3/pwnsat_tools` en `sys.path`).
- **La autoridad de los formatos de telemetría es `PWNSAT-C3/backend/tm_decoder.py`.** Cualquier TM que emita
  el emulador debe decodificar sin error ahí (ver `tests/test_tm_formats.py`).
- Comentarios/README/docs en **español**. Compatible **Ubuntu arm64/amd64 + macOS** (usar `python3`, no `python`).

## Estructura

```
vulsat                      # launcher bash: ./vulsat {sat|c3|attack NN|login|release|reconnect}
vulsat_sim/                 # el emulador (paquete python)
  satellite_core.py         # "firmware": estado + dispatch por APID + builders de TM + GPS + crash/reboot
  telemetry.py              # TelemetryScheduler: cadencias + due() puro (cold-start en __main__)
  pty_link.py               # DOS PTY (C3 + atacante) sobre el mismo core; framing 0xAA55 in / 0xAA out
  tui.py                    # dashboard de órbita/subsistemas en terminal (render() puro)
  eavesdrop.py              # lector pasivo del PoC 01 (decodifica telemetría en vivo)
  ptycompat/sitecustomize.py# shim pyserial para abrir PTY a 921600 en macOS/Linux
  vendored.py               # pone pwnsat_tools en sys.path
  __main__.py               # ensambla core+pty+scheduler+tui; cold-start; auto-reboot tras crash
PWNSAT-C3/                  # ground station vendored (NO EDITAR)
attacks/                    # PoCs 00-03 + lib vendored (NO EDITAR)
tests/                      # pytest (59): core, AES, crash, telemetría byte-exacta, pty, tui, integración
docs/                       # spec de telemetría/GPS/doble-PTY y specs/plans de diseño
requirements.txt  pyproject.toml  README.md
```

## Cómo correrlo (3 terminales)

```bash
pip install -r requirements.txt       # pyserial, pycryptodome, fastapi, uvicorn, itsdangerous, pytest
./vulsat sat                          # T1: emulador (TUI de órbita); publica .c3_port y .sat_port
./vulsat c3                           # T2: C3 apuntado al emulador -> http://127.0.0.1:8000 (operator/pwnsat) -> FlatSat
# T3 (ataques; ya NO hace falta release/reconnect por el doble PTY):
./vulsat attack 00                    # recon/enum APID
./vulsat attack 01 --seconds 10       # eavesdrop (telemetría en vivo)
./vulsat attack 02                    # fuzzing -> CRASH + reboot (visible en C3 y la TUI)
./vulsat attack 03 --power 255        # inyección de thruster sin auth
python3 -m pytest                     # 59 tests
```

## Protocolo / telemetría (resumen)

- Framing de línea: tierra→sat `0xAA 0x55 <len:2 BE> <SPP>`; sat→tierra `0xAA <SPP>`.
- AES-128-ECB con clave de lab; C3 asume secure-link ON → **todo TM sale cifrado** (`_reply`/builders) cuando
  `aes_enabled`. Todo payload de TM empieza con `spacecraft_id = 1`.
- TM implementados byte-exactos contra `tm_decoder`: STATUS(0x0C), NAV(0x0E), SENSOR(0x08), MISSION_MODE(0x0D),
  PAYLOAD_STATUS(0x0F), GS_STATUS(0x13), PING(0x01), ERROR(0x09), AES_CONFIG(0x0A), FIRMWARE(0x03).
- **GPS**: satélite arranca sobre **Cartago, CR** (9.8638, -83.9195), traza se mueve en `tick()` (lon lineal,
  lat sinusoidal, alt ~500 km); **ground station en México** (CDMX 19.4326, -99.1332); `GS_STATUS.distance_m` =
  haversine clampeado a u16, `within_range` si < radio (60 km). Modelo simplificado, no propagación orbital real.
- Vulnerabilidades modeladas: 00 clasificación real/ERROR(0x09)/silencio; 02 BROADCAST(0x06) payload 0 →
  crash + reboot (~8 s); 03 SET_THRUSTER(0x04) aplicado sin validar auth.

## Gotchas resueltos (importantes para no re-romper)

- **pyserial + PTY a 921600 en macOS**: `serial.Serial(pty, 921600)` falla (`Inappropriate ioctl`). El shim
  `vulsat_sim/ptycompat/sitecustomize.py` (inyectado por el launcher en `c3`/`attack` vía `PYTHONPATH`) clampea
  el baud a 115200 **solo en PTY** (`ttys*`/`pts/*`); hardware real intacto. En un PTY el baud es cosmético.
- **Escrituras a PTY sin lector CONGELABAN el emulador**: `send_tm` escribía bloqueante a ambos masters; el
  puerto de ataque normalmente no tiene lector → su buffer se llena → `os.write` bloquea → se frena telemetría
  y `tick()` (dashboard en "NO SIGNAL"). **Fix**: ambos masters en `O_NONBLOCK`; un puerto lleno lanza
  `BlockingIOError` y se descarta el frame para ese puerto, sin frenar al satélite. (Ver `pty_link.py`.)
- **`/ws` 403 / "NO SIGNAL" tras reiniciar C3**: C3 genera `SESSION_SECRET_KEY` aleatoria por arranque e
  invalida la cookie del navegador → el websocket queda en 403. **Fix**: el launcher `c3` fija
  `PWNSAT_C3_SECRET_KEY` por defecto (overrideable) para que el login sobreviva reinicios.
- **Rutas de los PoCs**: `attacks/lib/flatsat_usb.py` hace `sys.path.insert` a `PWNSAT-C3-Release/pwnsat_tools`
  (layout upstream). Acá es `PWNSAT-C3/pwnsat_tools` → el launcher `attack` lo antepone en `PYTHONPATH`.
- **Procesos duplicados**: dejar varios `vulsat_sim`/`uvicorn` vivos entremezcla telemetría en los puertos y
  confunde el diagnóstico. Al depurar, matar todo primero:
  `pkill -f vulsat_sim ; pkill -f "uvicorn backend"` y `rm -f .sat_port .c3_port`.

## Estado

- 3 features (telemetría real + GPS Cartago/México + doble PTY) implementadas, **verificadas en vivo** en el
  dashboard de C3, y publicadas en `main`. 59 tests verde.
- **Pendiente**: validación en Ubuntu arm64/amd64 (el código es portable; falta correrlo allí).
