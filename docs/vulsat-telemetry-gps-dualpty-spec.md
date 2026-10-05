# VUL-SAT — Spec: telemetría real + GPS + doble PTY

Objetivo: que el dashboard de PWNSAT-C3 muestre TODOS los paneles con datos (hoy
casi todos vacíos), simular GPS sobre **Cartago, Costa Rica** con la ground station
en **México**, y exponer **dos puertos serie** (uno para C3, otro para los ataques)
para no necesitar release/reconnect.

Autoridad de formatos: `PWNSAT-C3/backend/tm_decoder.py` (NO editarlo). Todos los
payloads son **little-endian** y **empiezan con `spacecraft_id` (1 byte, = 0x01)**.
Todo TM sale por `_reply`/builder → cifrado AES cuando `aes_enabled` (C3 asume link
seguro por defecto).

## 1. Formatos de telemetría a emitir (byte-exactos)

`spacecraft_id = 1` siempre. Flags por defecto:
- `status_flags` (mission.h): BME_OK 0x01 | ACC_OK 0x02 | GPS_UART_OK 0x04 | GPS_FIX 0x08 |
  SECURE_LINK 0x10 | GPS_NMEA_ACTIVE 0x80  → 0x9F (sin PAYLOAD_ARMED, sin USB_DEBUG).
  Si `aes_enabled` es False, quitar el bit SECURE_LINK (0x10).
- `gps_status_flags`: UART_OK 0x01 | CONNECTED 0x02 | NMEA_ACTIVE 0x04 | FIX_VALID 0x08 |
  TIME_VALID 0x10 → 0x1F.
- `gps_sats` = 9.
- fw version: major=1, minor=3, patch=0  (orden en STATUS: patch, minor, major).

### STATUS (APID 0x0C) — decode_mission_status, 26 bytes
Bytes 0..7: `spacecraft_id, mission_mode, status_flags, gps_status_flags, beacon_interval_s, thruster0, thruster1, gps_sats`
Luego `struct.pack("<HHIBBBBBHBBB", payload_fwd_count, last_payload_freq, uptime_s, utc_hour, utc_minute, utc_second, utc_day, utc_month, utc_year, fw_patch, fw_minor, fw_major)`
- mission_mode = state.mode numérico (ver §4), beacon_interval_s = state.beacon_rate_s,
  thruster0/1 = state.thruster, uptime_s = state.uptime_s, payload_fwd_count=0, last_payload_freq=0.
- UTC = hora real (datetime.utcnow()).

### NAV (APID 0x0E) — decode_nav, 30 bytes
Bytes 0..2: `spacecraft_id, gps_status_flags, gps_sats`
`struct.pack("<iii", lat_e7, lon_e7, alt_cm)` (offset 3)
Bytes 15..19: `utc_hour, utc_minute, utc_second, utc_day, utc_month`
`struct.pack("<H", utc_year)` (offset 20)
`struct.pack("<hhhh", accel_x_cent, accel_y_cent, accel_z_cent, accel_temp_cent)` (offset 22)
- lat_e7/lon_e7 = posición GPS actual (§3) en grados*1e7 (int). alt_cm = altitud en cm
  (LEO ~500 km → 50_000_000 cm, entra en i32).
- accel_*_cent = valor*100 como int16: p.ej. accel_z=981 (1g), x=y≈0 con leve ruido, temp=2500.

### SENSOR (APID 0x08 SEND_TM) — decode_sensor_tm, 19 bytes
Byte 0: spacecraft_id. Luego `struct.pack("<8h", accel_x, accel_y, accel_z, accel_temp, bme_temp, bme_pressure, bme_altitude, bme_humidity)` (todos *100, int16, deben entrar en -32768..32767). Luego 2 bytes crudos: thruster0, thruster1.
- Valores que ENTRAN en int16*100: accel_z=981, accel_x/y≈0..200, accel_temp=2500 (25°C),
  bme_temp=2250 (22.5°C), bme_pressure= usar 8700 (→87.00; hPa real desborda int16, documentar
  que va escalado), bme_altitude= p.ej. 30000 (→300.0 m — o la alt del sat/100 si entra; si no, un valor fijo),
  bme_humidity=5500 (55%). Elegir valores plausibles que NO desborden int16.

### MISSION_MODE (APID 0x0D) — decode_mission_mode, 4 bytes
`spacecraft_id, mission_mode, payload_armed(0), status_flags`.

### PAYLOAD_STATUS (APID 0x0F) — decode_payload_status, 8 bytes
Bytes 0..3: `spacecraft_id, mission_mode, payload_armed(0), secure_link_enabled(1 si aes on)`
`struct.pack("<HHBB", last_payload_freq(0), payload_fwd_count(0), last_payload_len(0), 0)`

### GS_STATUS (APID 0x13) — decode_gs_status, 23 bytes
Bytes 0..2: `spacecraft_id, gs_status_flags, gps_status_flags`
`struct.pack("<HHIHiiH", distance_m, session_remaining_s(0), challenge(0), handshake_remaining_s(0), gs_lat_e7, gs_lon_e7, gs_radius_m)`
- GS en México (Ciudad de México): gs_lat_e7 = 194326000 (19.4326), gs_lon_e7 = -991332000 (-99.1332).
- gs_radius_m = 60000 (60 km, cabe en u16).
- distance_m = distancia haversine entre la posición GPS del sat (§3) y la GS, en metros,
  **clampeada a 65535** (u16). within_range = distance < gs_radius_m.
- gs_status_flags: GPS_VALID 0x02 | GATE_OPEN 0x20 siempre; agregar WITHIN_RANGE 0x04 si within_range.

### PING (APID 0x01) — decode_ping_ack
payload = `bytes([spacecraft_id]) + b"PONG"` (texto ASCII tras el id).

### ERROR (APID 0x09) — decode_error
payload = mensaje ASCII (sin spacecraft_id), p.ej. `b"APID not implemented"`. (El recon
clasifica por APID 0x09, así que el contenido es libre pero debe ser ASCII.)

### AES_CONFIG (APID 0x0A) — decode_aes_config
payload = `bytes([spacecraft_id, 1 if aes_enabled else 0])`.

### FIRMWARE (APID 0x03) — decode_firmware_version (para el botón/attack SEND_FW)
payload = `bytes([spacecraft_id, patch=0, minor=3, major=1])`. (Opcional; si no estaba, agregarlo.)

## 2. Cadencias de emisión (en __main__ loop / scheduler)
- STATUS 0x0C: cada ~5 s (hoy 14) — es el que llena MODE/UPTIME/SECURE LINK/THRUSTERS/health.
- NAV 0x0E: cada ~3 s (posición/accel).
- SENSOR 0x08: cada ~6 s.
- GS_STATUS 0x13: cada ~4 s.
- PAYLOAD_STATUS 0x0F: cada ~10 s.
- MISSION_MODE 0x0D: cada ~10 s (o junto con STATUS).
Emitir un ciclo completo de cada uno inmediatamente al arrancar (cold-start) para que el
dashboard no quede en blanco. Mantener la lógica de crash (no emite nada mientras crashed).

## 3. Modelo GPS (Cartago CR → órbita, GS México)
- Posición inicial sobre **Cartago, Costa Rica**: lat 9.8638, lon -83.9195 (e7: 98638000, -839195000).
- Movimiento: simular avance de la traza terrestre. Modelo simple suficiente para la demo:
  la longitud avanza con el tiempo (p.ej. +0.05°/s aprox, envolviendo en ±180), la latitud
  oscila sinusoidalmente con amplitud ~ inclinación (p.ej. ±20° alrededor de la lat inicial,
  acotada a ±85). alt_cm fija ~500 km. Mantener `state.lat_e7/lon_e7/alt_cm` en el estado y
  avanzarlos en `tick()`.
- GS fija en **México** (CDMX 19.4326, -99.1332).
- distance_m (GS_STATUS) = haversine(sat, GS) en metros, clamp u16, within_range si < radio.
- La TUI del emulador debería mostrar lat/lon actuales (agregar a render()).

## 4. mission_mode
Definir `state.mode` como entero con nombre para la TUI. Usar p.ej. 0=NOMINAL. Mantener el
string `state.mode` actual para la TUI pero emitir un entero en los TM (map nombre→int; default 0).
No romper los tests existentes que leen state.mode como string (ajustar: usar state.mode como
string para la TUI y una constante MODE_NUM para el TM, o un dict).

## 5. Doble PTY (C3 + atacante)
- `PtyLink` debe exponer DOS slaves apuntando al mismo SatelliteCore:
  - puerto C3 → publicado en `.c3_port`
  - puerto atacante → publicado en `.sat_port` (mantener este nombre para los PoCs/launcher attack)
- La telemetría periódica se **difunde a AMBOS** masters. Los TC entrantes de CUALQUIERA de
  los dos se procesan por el core (pump_once lee de ambos masters).
- Así C3 queda conectado permanentemente mientras los ataques usan el otro puerto —
  **sin release/reconnect**.
- Launcher: `vulsat c3` usa `$(cat .c3_port)`; `vulsat attack NN` usa `$(cat .sat_port)`.
  `release`/`reconnect` quedan como no-op o se eliminan del README (ya no hacen falta).
- `close()` borra ambos .c3_port y .sat_port.
- Nota portabilidad: mantener el shim pyserial (pts/ttys) y `python3`.

## 6. Tests
- Actualizar/crear tests byte-exactos: cada builder produce un payload que `tm_decoder.decode(apid, plano)`
  parsea sin error y con los campos esperados (lat/lon de Cartago, GS México, flags, uptime, thruster).
  Importar el decoder vendored vía la ruta de pwnsat_tools/backend (usar sys.path a PWNSAT-C3).
- Test de doble PTY: TC por el puerto atacante cambia el estado y C3-port recibe telemetría.
- Mantener verdes los tests existentes (ajustar los de STATUS/NAV viejos al nuevo formato).
- Round-trip AES intacto. Crash/reboot intacto.

## 7. No romper
- Los 4 PoCs (00-03) deben seguir funcionando (ahora por el puerto atacante).
- AES on/off, crash/reboot, recon (ERROR 0x09) intactos.
- No editar PWNSAT-C3/ ni attacks/. Comentarios en español. Compatible Ubuntu arm64/amd64 + macOS.
