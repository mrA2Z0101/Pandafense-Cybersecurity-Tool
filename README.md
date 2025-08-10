# Pandafense-Cybersecurity-Tool
Cybersecurity Defense tool that uses the ESP32 Microcontroller
![Add a heading](https://github.com/user-attachments/assets/b9cf820b-354a-4c15-83ea-c732a261be5f)

# Pandafense

*A pocket defender that scans Wi‑Fi now. Bluetooth and RF next. When danger shows up, a panda frowns.*

![demo-gif](docs/demo.gif)

> **Status:** Prototype. Wi‑Fi detectors are working. A first **BLE Jam Detector** is included. Other BLE and sub‑GHz modules will follow.

---

## ⚠️ Warning — Legal & Ethical Use Only

This project is for **education, research, and defensive security**. By using it, you agree to:

* **Only scan/test networks and devices you own** or have **explicit written permission** to assess.
* **Never disrupt wireless service.** Do **not** transmit deauthentication, beacon‑flood, or jamming signals. Those are illegal in many jurisdictions.
* Follow local **radio regulations** (e.g., FCC/ETSI) and applicable laws.
* Use shielded labs or controlled environments for demonstrations, with informed consent from all parties.

> **This repository ships only detection code.** There is **no attack/transmit functionality** provided. The maintainers are **not responsible** for misuse. If you believe any content violates GitHub’s Acceptable Use Policies, please open an issue so it can be addressed.

---

## ✨ Features (today)

* **Wi‑Fi Deauth detector** – flags 802.11 deauthentication frames.
* **Wi‑Fi Rogue AP detector** – tracks SSIDs across channels and alerts on suspicious multi‑channel clones.
* **Wi‑Fi ARP spoof detector** – notices multiple MACs claiming the same IP (best on open networks).
* **Wi‑Fi Beacon‑flood detector** – detects abnormal beacon spikes per SSID.
* **BLE Jam detector (prototype)** – watches BLE ADV rates and alerts on sustained drops consistent with jamming.
* **On‑device UI** – a panda on an OLED. Scanning = looking around. Alert = sad face + LEDs + buzzer.

> **Single‑button UX.** Short press = next. Long press (\~1.5 s) = select. Long press while active = stop and go back.

---

## 🧩 Why

Hands‑on defense training. See what common attacks look like over the air. Demo in a lab you control. Teach without walls of text.

---

## 📦 Hardware (this build)

| Part                          | Notes                                   |
| ----------------------------- | --------------------------------------- |
| **ESP32** dev board           | Wi‑Fi promiscuous mode. BLE via NimBLE. |
| **OLED SSD1306 128×64 (I²C)** | UI and panda animation.                 |
| **LED (RED)**                 | Alarm indicator. **GPIO 2**.            |
| **LED (GREEN)**               | Heartbeat/OK. **GPIO 13**.              |
| **Piezo buzzer**              | Audible alert. **GPIO 18**.             |
| **Momentary button**          | Input. **GPIO 14** (INPUT\_PULLUP).     |

**Power & wiring**

* OLED on **3V3**, GND, **SDA/SCL** per your board. Default I²C address **0x3C**.
* Button to **GND**. Uses internal pull‑up.

### 🔌 Wiring diagram

**Typical ESP32 DevKit (I²C pins 21/22)**

```
ESP32 (DevKit)           SSD1306 128x64 (I²C)
-----------------------  ---------------------
3V3                      VCC
GND                      GND
GPIO21 (SDA)             SDA
GPIO22 (SCL)             SCL

ESP32                    Other parts
-----------------------  ---------------------
GPIO14                   Button → GND  (INPUT_PULLUP)
GPIO2                    Red LED anode → 220Ω → pin ; cathode → GND
GPIO13                   Green LED anode → 220Ω → pin ; cathode → GND
GPIO18                   Buzzer + → pin ; Buzzer − → GND
```

> Some ESP32 boards map I²C to different pins. If needed, call `Wire.begin(SDA, SCL)` with your pins, or rewire to the board’s labeled SDA/SCL.

![wiring-diagram](hardware/wiring-diagrams/pandafense_esp32_ssd1306_i2c.png)

---

## 🗂️ Repo structure

```
Pandafense/
├─ firmware/
│  ├─ arduino/
│  └─ platformio/
├─ hardware/
│  ├─ wiring-diagrams/
│  └─ enclosure/
├─ docs/
│  ├─ demo.gif
│  └─ screenshots/
└─ LICENSE
```

---

## 🧰 Dependencies

* **ESP32 Arduino Core**
* **Adafruit\_GFX** and **Adafruit\_SSD1306**
* **NimBLE‑Arduino** (by h2zero)

> Some NimBLE versions change callback signatures. This project uses `NimBLEScanCallbacks` and `setScanCallbacks(&cb, /*wantDuplicates=*/true)`.

---

## 🚀 Quick start

### Arduino IDE

1. Install ESP32 board support.
2. Install the libraries above.
3. Open `firmware/arduino` and build/flash.

### PlatformIO

1. Open `firmware/platformio` in VS Code.
2. `pio run -t upload`.

If the OLED stays blank, scan I²C and confirm **0x3C**. Adjust in the config if needed.

### 🛠️ Minimal PlatformIO config

Create `firmware/platformio/platformio.ini`:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
upload_speed = 921600

lib_deps =
  adafruit/Adafruit GFX Library
  adafruit/Adafruit SSD1306
  h2zero/NimBLE-Arduino

build_flags =
  -D OLED_ADDR=0x3C
  -D CORE_DEBUG_LEVEL=0
```

Project layout expected by PlatformIO:

```
firmware/platformio/
├─ platformio.ini
└─ src/
   └─ main.cpp   ← paste your sketch here (convert .ino to .cpp if needed)
```

---

## 🕹️ Using the device

**Main menu**

* **Wi‑Fi Defense**
* **Bluetooth Defense**

**Wi‑Fi submenu**

* Deauth Detector
* Rogue AP Detector
* ARP Spoof Detector
* Beacon‑Flood Detector
* Menu (back)

**Bluetooth submenu**

* BLE Scan Detector (placeholder)
* BLE Spoof Detector (placeholder)
* BLE Flood Detector (placeholder)
* **BLE Jam Detector** (implemented)
* Menu (back)

**Controls**

* Short press cycles the cursor.
* Long press selects. Long press in a sub‑menu returns to the main menu.
* While active, long press stops scanning and returns home.

**Indicators**

* **Green LED ON** when idle/OK. **Red LED + buzzer** when any alert is active.
* Screen shows the panda. Happy when scanning. Sad when an alert triggers.

---

## 🔎 Detection details (matches source code)

### Deauth

* Listens for 802.11 management frames with subtype **Deauthentication**.
* Any hit sets `deauthDetected` and raises an alert for `ALERT_DURATION`.

### Rogue AP

* Tracks **SSIDs** and the **set of channels** they appear on (`channelsSeen` bitmask).
* When a known SSID shows up on **new channels** repeatedly within **NEW\_CHANNEL\_WINDOW**, increments a counter.
* If the counter reaches **NEW\_CHANNEL\_THRESHOLD (3)** and the BSSID OUI is **not in the whitelist**, it alerts.
* Persistence: SSIDs and channel bitmasks are saved in ESP32 **Preferences** under the `apstore` namespace.

### ARP spoof

* Parses data frames for **LLC/SNAP** type **0x0806** (ARP). Looks for **ARP replies** (op=2).
* Maps `IP → {MACs...}` and alerts when **multiple MACs** claim the same IP.
* Works best on **open/unencrypted** networks. Encrypted payloads will hide ARP without association.

### Beacon flood

* Counts beacons per **SSID** within a sliding window. Triggers when counts exceed **BEACON\_THRESHOLD (100)** in **BEACON\_WINDOW\_MS (1000 ms)**.

### BLE jam (prototype)

* Uses NimBLE continuous active scan. Measures **advertisements per second (pps)** in **WINDOW\_MS (3000 ms)** windows.
* Builds a baseline after **WARMUP\_MS (15000 ms)** and **MIN\_BASELINE\_COUNT (60)** frames.
* Alerts when **pps < LOW\_RATIO × baseline** for **LOW\_WINDOWS\_TO\_ALERT (3)** windows.

---

## ⚙️ Configuration constants

```cpp
// Button and debounce
const unsigned long DEBOUNCE_DELAY  = 50;      // ms
const unsigned long LONG_PRESS_TIME = 1500;    // ms

// Wi‑Fi scanning
static const unsigned long CHANNEL_HOP_INTERVAL = 200;   // ms, cycles 1–13
static const unsigned long ALERT_DURATION       = CHANNEL_HOP_INTERVAL * 13 + 500; // visual/audio alert hold
static const unsigned long ROGUE_TIMEOUT        = 500;   // ms
static const unsigned long ARP_TIMEOUT          = 500;   // ms
static const unsigned long BEACON_WINDOW_MS     = 1000;  // ms
static const int           BEACON_THRESHOLD     = 100;   // per SSID per window
static const unsigned long NEW_CHANNEL_WINDOW   = 60000; // ms
static const int           NEW_CHANNEL_THRESHOLD= 3;     // hits before rogue

// OUI whitelist for allowed AP vendors
#define NUM_WHITELIST_OUIS 1
const uint8_t whitelistOUI[NUM_WHITELIST_OUIS][3] = { {0xAA,0xBB,0xCC} };

// OLED
#define OLED_ADDR 0x3C
```

Change GPIOs and thresholds as needed, then rebuild.

---

## 📈 Tuning and testing

* Take a **baseline** in a quiet room. Note beacon and deauth counts.
* Trigger detections in a **controlled lab** on gear you own.
* If rogue AP alerts too easily, raise `NEW_CHANNEL_THRESHOLD` or add OUIs you trust.
* Beacon floods vary by environment. Tweak `BEACON_THRESHOLD` and window length.
* BLE jam detection is heuristic. Expect false positives in very quiet rooms.

---

## 🧱 Limitations

* Focuses on **2.4 GHz** today. Channel hop spans 1–13.
* ARP spoof detection is limited on **encrypted** WLANs without association.
* Promiscuous capture can miss frames during heavy bursts.
* BLE jam logic uses traffic statistics. It does **not** demodulate or measure RF energy directly.

---

## 🗺️ Roadmap

* Implement BLE **Scan/Spoof/Flood** detectors.
* Add **NRF24L01+** and **CC1101** RF scans.
* On‑device **config menu**.
* **SD card** or serial logging.
* **JSON** telemetry for dashboards.
* Unit tests for parsers.

Open an issue if you want to help with any item.

---

## 🧪 Classroom/lab demos

* **Deauth**: Small burst on a lab AP and client you own. Watch the alert.
* **Rogue AP**: Clone SSID on another channel. Avoid OUIs on your whitelist.
* **Beacon flood**: Short beacon spam burst near the device.
* **ARP spoof**: On an open lab network, run a local ARP poisoner. Observe the conflict.

Keep power low. Do not interfere with others. Get written approval in shared spaces.

---

## 🧰 Troubleshooting

* **No OLED output**: Check 3V3 and GND. Confirm I²C address 0x3C.
* **Button unresponsive**: Verify wiring to GPIO 14 and pull‑up. Adjust `LONG_PRESS_TIME`.
* **No Wi‑Fi detections**: Ensure promiscuous mode is enabled. Try a quieter RF space. Confirm channel hopping.
* **NimBLE compile errors**: Use `NimBLEScanCallbacks` and `onResult(const NimBLEAdvertisedDevice*)`. Some versions omit `onScanEnd`.

---

## 🤝 Contributing

PRs and issues welcome. Please describe steps to reproduce, your test setup, and proposed changes. Keep functions small. Document parsing logic.

---

## 📄 License

MIT. See `LICENSE`.

---

## 🙏 Credits

Thanks to the Arduino, ESP32, and NimBLE communities. And to security educators who model safe, legal testing.

---

## 📚 FAQ

**Is this legal?** Use it on your own gear or in a lab you control. Learn the rules where you live.

**Does ARP detection work on WPA2/WPA3?** Only if the traffic is visible. On encrypted WLANs without association, ARP payloads are not readable.

**Why a panda?** Security tools can feel harsh. The panda keeps it friendly while you learn.
