![Add a heading](https://github.com/user-attachments/assets/b9cf820b-354a-4c15-83ea-c732a261be5f)

# PandaFense

**ESP32 Wi‑Fi + BLE Threat Detectors · RF Tools (CC1101) · OLED UI · WebUI · Honeypots**

PandaFense is a handheld network defense toy and teaching tool. It scans Wi‑Fi and BLE for noisy or suspicious behavior. It adds Sub‑GHz RF tools with a CC1101. It serves a simple WebUI for control and live alerts. It also ships with small deception modules (honeypots) to study hostile behavior.

> ⚠️ Use only on networks and spectrum you own or have permission to test. Local laws vary.

---

## Highlights

* **One‑button UI** on a 128×64 I²C OLED

  * Short press: move cursor
  * Long press: select / back
* **Wi‑Fi Defense** (14 single‑mode detectors): Deauth, Rogue AP, ARP spoof, Beacon flood, Disassoc, Probe flood, RTS/CTS flood, EAPOL storm, CSA, Spoofed mgmt, Beacon anomaly, WPS spam, RSN mismatch, Broadcast data
* **Bluetooth Defense**

  * 10 scan‑only detectors
  * BLE Jam heuristic detector
* **RF Tools** (CC1101)

  * Band scan, Simple monitor, Waterfall, OOK edge capture, 2‑FSK capture, IDS (jam/flood)
  * Presets and on‑the‑fly tuning via HTTP
  * Save captures to SPIFFS and download
* **Honeypots**

  * Fake AP + DNS catcher (logs hostnames)
  * Credential portal (captures username+password, masks in WS alerts)
  * Telnet/SSH banner + credential logger
  * BLE Beacon honeypot (advertises a service and logs connects)
* **WebUI** (HTTP + WebSocket)

  * Live status and alert stream
  * Start/stop detectors over HTTP
  * RF configuration endpoints
  * mDNS: `http://pandafense.local` (when mDNS active)
* **Dashboard gating**

  * AP + Web server start only after you pick **Dashboard → Yes** on device
* **Settings**

  * Sound On/Off
  * Overlay On/Off (hide panda, show text alerts)
* **Persistence**

  * Stores AP sketches and UI prefs in NVS (Preferences)

---

## Hardware

* **MCU:** ESP32 Dev‑Kit (Arduino core v3.x)
* **Display:** 0.96" SSD1306 I²C OLED, 128×64, addr `0x3C`
* **RF:** CC1101 SPI transceiver
* **Inputs/Outputs:** one button, red/green LED, buzzer

### Pin Map (ESP32)

| Function         | Pin                 |
| ---------------- | ------------------- |
| Button           | GPIO 14             |
| Red LED          | GPIO 2              |
| Green LED        | GPIO 26             |
| Buzzer           | GPIO 18             |
| **OLED I²C SDA** | GPIO 21 *(default)* |
| **OLED I²C SCL** | GPIO 22 *(default)* |
| **CC1101 CS**    | GPIO 5              |
| **CC1101 GDO0**  | GPIO 4              |
| **CC1101 SCK**   | GPIO 25             |
| **CC1101 MISO**  | GPIO 27             |
| **CC1101 MOSI**  | GPIO 33             |

> If your board uses different I²C pins, pass them to `Wire.begin(SDA,SCL)`.

<img width="1930" height="1200" alt="All the Parts" src="https://github.com/user-attachments/assets/3db95738-be51-4590-9e24-5e7f48c6513d" />

<img width="1930" height="1200" alt="ESP32 and OLED Screen" src="https://github.com/user-attachments/assets/370b0d7b-c64f-429c-b96f-fbbf879cc642" />

<img width="1930" height="1200" alt="ESP32 and CC1101 Module" src="https://github.com/user-attachments/assets/ec19649c-cdbc-42d1-bbd7-be0d3005afcf" />

<img width="1930" height="1200" alt="ESP32, tactile button, LED Diodes and Buzzer" src="https://github.com/user-attachments/assets/11806c96-6e13-4d1b-aa58-17fe831ccb72" />


---

## Libraries

Install these in Arduino IDE or your build system:

* **Adafruit GFX** and **Adafruit SSD1306**
* **NimBLE‑Arduino**
* **ESP Async WebServer** and **AsyncTCP**
* **ESPmDNS**, **SPIFFS**, **FS**, **DNSServer**, **AsyncUDP** (part of ESP32 core v3.x)
* **ELECHOUSE\_CC1101\_SRC\_DRV**

---

## Build & Flash

1. **Board Manager:** ESP32 by Espressif (v3.x)
2. **Partition scheme:** Default (SPIFFS enabled)
3. **Open code:** `PandaFense_*.ino`
4. **Adjust config:**

   * Wi‑Fi creds and token:

     ```cpp
     static const char* WIFI_SSID = "...";
     static const char* WIFI_PASS = "...";
     static const char* TOKEN     = "panda_token_123"; // change this
     ```
5. **Upload** and open Serial at **115200**.

> If STA connect fails, device falls back to SoftAP `Pandafense-AP` / `pandapass`.

---

## Device UI

**Main menu:** Wi‑Fi · Bluetooth · Dashboard · Settings · RF · Honeypots

* **Dashboard** → prompts: *Use your desktop?* → **Yes** starts AP+Web.
* **Settings** → Sound On/Off, Overlay On/Off, Menu
* **RF** → Band Scan, Monitor @Freq, Waterfall, OOK Edge, 2‑FSK, RF IDS, **Presets/Tuning**
* **Honeypots** → Fake AP, Telnet/SSH, Credential Portal, BLE Beacon, Menu

**Overlay Off** shows text alerts instead of the panda face on the OLED.

---

## WebUI & API

### Access

* **SoftAP:** `Pandafense-AP` / `pandapass` → `http://192.168.4.1/`
* **mDNS (if active):** `http://pandafense.local/`
* **Root:** serves `/index.html` from SPIFFS or an embedded minimal page
* **WebSocket:** `/ws` (status + alerts)

### Endpoints

* `GET  /api/status`
* `POST /api/cmd?action=set&detector=NAME&state=start|stop`
* `GET  /rf/status`
* `POST /rf/set`  *(mhz, bw\_khz, dr\_bps, mod, sync, thresh)*
* `POST /rf/preset` *(name)*
* `GET  /rf/files`  *(list captures)*
* `GET  /rf/download?file=<path>`

> **Auth:** Add header `Authorization: Bearer <TOKEN>` or `?token=...`.

### Detector names (for `/api/cmd`)

**Wi‑Fi:** `DEAUTH, ROGUE_AP, ARP, BEACON, DISASSOC, PROBE, RTSCTS, EAPOL, CSA, SPOOFEDMGMT, BEACON_ANOM, WPS, RSN_MISMATCH, BCAST_DATA`

**BLE:** `BT_ADV_FLOOD, BT_UUID_FLOOD, BT_ADDR_HOP, BT_SERVICE_SPOOF, BT_MFR_STORM, BT_SCANRSP_ABUSE, BT_INTERVAL_ANOM, BT_REPLAY_CLONE, BT_NAME_SQUAT, BT_RSSI_TELEPORT, BT_JAM`

**RF:** `RF_BANDSCAN, RF_MONITOR, RF_WATERFALL, RF_OOK_CAPTURE, RF_2FSK_CAPTURE, RF_IDS`

**Honeypots:** `HP_FAKE_AP, HP_TELNET, HP_CREDENTIAL, HP_BLE_BEACON`

### Examples

Start a detector:

```bash
curl -X POST http://pandafense.local/api/cmd \
  -H "Authorization: Bearer <TOKEN>" \
  -d 'action=set&detector=DEAUTH&state=start'
```

Tune RF:

```bash
curl -X POST http://pandafense.local/rf/set \
  -H "Authorization: Bearer <TOKEN>" \
  -d 'mhz=433.92&bw_khz=100&dr_bps=2400&mod=2&sync=1&thresh=-65'
```

Apply an RF preset:

```bash
curl -X POST http://pandafense.local/rf/preset \
  -H "Authorization: Bearer <TOKEN>" \
  -d 'name=US_433_OOK'
```

List and fetch captures:

```bash
curl -H "Authorization: Bearer <TOKEN>" http://pandafense.local/rf/files
curl -H "Authorization: Bearer <TOKEN>" -O "http://pandafense.local/rf/download?file=/rf/20250101_000000_OOK.bin"
```

### WebSocket payloads

**Status**

```json
{
  "event": "status",
  "payload": {
    "deviceId": "panda-01",
    "wifiReady": true,
    "apMode": true,
    "mode": 26,
    "modeName": "RF_BANDSCAN",
    "menuLevel": 2,
    "soundOff": false,
    "overlayOff": false
  }
}
```

**Alert** (keys vary by detector)

```json
{
  "event": "alert",
  "payload": {
    "deviceId": "panda-01",
    "detector": "DEAUTH",
    "severity": "HIGH|MEDIUM|LOW",
    "ts": 1234567,
    "details": { "rssi": -62, "note": "..." }
  }
}
```

---

## RF Presets (built‑in)

| Name          | Freq (MHz) | DR (bps) | RX BW (Hz) |   Mod |  Sync | Thresh |
| ------------- | ---------: | -------: | ---------: | ----: | ----: | -----: |
| US\_315\_OOK  |     315.00 |     2400 |     100000 |   OOK | 30/32 |    -65 |
| US\_433\_OOK  |     433.92 |     2400 |     100000 |   OOK | 30/32 |    -65 |
| EU\_433\_2FSK |     433.92 |    38400 |     203000 | 2‑FSK | 16/16 |    -70 |
| EU\_868\_2FSK |     868.30 |    50000 |     203000 | 2‑FSK | 16/16 |    -70 |
| US\_915\_2FSK |     915.00 |   100000 |     270000 | 2‑FSK | 16/16 |    -70 |
| US\_915\_OOK  |     915.00 |     4800 |     135000 |   OOK | 30/32 |    -65 |

> Uses ELECHOUSE CC1101 driver. `setSidle()` is used to idle the radio when stopping.

---

## Honeypots (quick notes)

* **Fake AP:** SoftAP + DNS catcher (AsyncUDP). Logs QNAMEs. Minimal HTML served.
* **Credential portal:** SoftAP with captive page. Logs creds to SPIFFS and Serial. WebSocket alerts mask the username mid‑section.
* **Telnet/SSH:** TCP servers on 23/22. Logs credentials and simple commands. Emits MEDIUM/HIGH alerts.
* **BLE Beacon:** NimBLE server advertises a service and characteristic. Logs connects/disconnects and restarts advertising.

All honeypot HTTP handlers use `hpLogHttp()` which both logs and raises LOW alerts.

---

## Persistence

* **Preferences (NVS):**

  * `apstore`: `apCount`, `ssidN`, `chmN` (per row)
  * `soundOff`, `overlayOff`
* **SPIFFS:**

  * `/rf/*.bin` for OOK/2FSK captures
  * `/honeypot_events.csv` for honeypot logs

---

## Troubleshooting

* **401 Unauthorized:** set `TOKEN` in code. Pass `Authorization: Bearer <TOKEN>`.
* **CORS in browser:** basic `*` CORS is enabled. If you add custom headers, adjust defaults.
* **OLED blank:** confirm I²C address `0x3C`. Check SDA/SCL pins.
* **CC1101 idle error:** library uses `setSidle()` (not `setIdle()`). The code already calls `setSidle()` when stopping.
* **No WebUI:** Start **Dashboard → Yes** to bring up AP + server.

---

## Roadmap

* SD card logging for long RF captures
* CSV/PCAP exports for BLE and Wi‑Fi counters
* On‑device RF waterfall view on OLED (tiny)
* Honeypot modules: mDNS responder, simple MQTT trap, UPnP/SSDP bait
* Optional multi‑button UI

---

## Legal

This project is for education and research. Follow local regulations for wireless testing. Do not intercept traffic without consent.

---

## Credits

* ESP32 Arduino core, NimBLE‑Arduino, ELECHOUSE CC1101 driver, Adafruit GFX/SSD1306, Async WebServer/AsyncTCP.
