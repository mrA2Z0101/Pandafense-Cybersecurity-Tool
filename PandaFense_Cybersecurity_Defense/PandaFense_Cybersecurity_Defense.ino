//Name: Pandafense
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <Arduino.h>
#include <Preferences.h>
#include <NimBLEDevice.h>   // NimBLE-Arduino by h2zero

// ── HARDWARE PINS ──
#define BUTTON_PIN       14
#define RED_LED_PIN      2
#define GREEN_LED_PIN    13
#define BUZZER_PIN       18

// ── OLED CONFIG ──
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ── MENU LEVELS ──
enum MenuLevel { MAIN = 0, SUBMENU = 1, ACTIVE = 2 };
MenuLevel menuLevel = MAIN;

// ── MAIN MENU ──
const char* mainItems[] = { "Wi-Fi Defense", "Bluetooth Defense" };
int mainIndex = 0;
const int MAIN_COUNT = 2;

// ── SUBMENUS ──
const int SUB_COUNT = 5;
const char* wifiItems[SUB_COUNT] = {
  "Deauth Detector",
  "Rogue AP Detector",
  "ARP Spoof Detector",
  "Beacon-Flood Detector",
  "Menu"
};
const char* btItems[SUB_COUNT] = {
  "BLE Scan Detector",
  "BLE Spoof Detector",
  "BLE Flood Detector",
  "BLE Jam Detector",
  "Menu"
};
int subIndex = 0;
bool inWifiSub = true;

// ── OPERATION MODES ──
enum Mode {
  MODE_NONE = 0,
  MODE_DEAUTH = 1,
  MODE_ROGUE = 2,
  MODE_ARP    = 3,
  MODE_BEACON = 4,
  MODE_BT0    = 5,
  MODE_BT1    = 6,
  MODE_BT2    = 7,
  MODE_BT3    = 8   // BLE Jam Detector
};
Mode mode = MODE_NONE;

// ── BUTTON STATE ──
bool    lastRaw       = HIGH;
unsigned long lastDebounce = 0;
unsigned long pressStart   = 0;
const unsigned long DEBOUNCE_DELAY  = 50;
const unsigned long LONG_PRESS_TIME = 1500;

// ── SCAN & ALERT PARAMETERS ──
static const unsigned long CHANNEL_HOP_INTERVAL = 200;
static const unsigned long ALERT_DURATION       = CHANNEL_HOP_INTERVAL * 13 + 500;
static const unsigned long ROGUE_TIMEOUT        = 500;
static const unsigned long ARP_TIMEOUT          = 500;
static const unsigned long BEACON_WINDOW_MS     = 1000;
static const int           BEACON_THRESHOLD     = 100;
static const unsigned long NEW_CHANNEL_WINDOW   = 60000;
static const int           NEW_CHANNEL_THRESHOLD= 3;

// ── WHITELIST OUI ──
#define NUM_WHITELIST_OUIS 1
const uint8_t whitelistOUI[NUM_WHITELIST_OUIS][3] = { {0xAA,0xBB,0xCC} };

// ── STATE & TRACKING ──
volatile unsigned long lastDeauthTime = 0;
volatile bool        deauthDetected   = false;
volatile unsigned long lastRogueTime  = 0;
volatile bool        rogueDetected    = false;
volatile unsigned long lastARPTime    = 0;
volatile bool        arpDetected      = false;
volatile unsigned long lastBeaconTime = 0;
volatile bool        beaconDetected   = false;
static uint8_t       currentChannel   = 1;
static unsigned long lastChannelHop   = 0;

// ── BLE JAM DETECTION STATE ──
volatile bool        bleJamDetected   = false;
volatile unsigned long lastBleJamTime = 0;

namespace BLEJAM {
  static const uint32_t WINDOW_MS            = 3000;
  static const uint32_t WARMUP_MS            = 15000;
  static const int      LOW_WINDOWS_TO_ALERT = 3;
  static const float    LOW_RATIO            = 0.15f;
  static const float    MIN_BASELINE_PPS     = 2.0f;
  static const int      MIN_BASELINE_COUNT   = 60;

  volatile uint32_t windowCount = 0;
  volatile uint32_t totalCount  = 0;

  unsigned long windowStart = 0;
  unsigned long startTime   = 0;
  float         baselinePPS = 0.0f;
  bool          baselineReady = false;
  int           lowWindows  = 0;

  NimBLEScan* scan = nullptr;

  // Use NimBLEScanCallbacks; older versions expect const param and may not have onScanEnd.
  class ScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* d) override {
      windowCount++;
      totalCount++;
      (void)d;
    }
  } scanCB;

  void start() {
    static bool inited = false;
    if (!inited) { NimBLEDevice::init(""); inited = true; }

    scan = NimBLEDevice::getScan();
    // If your installed version doesn't accept the 2nd arg, drop it: setScanCallbacks(&scanCB);
    scan->setScanCallbacks(&scanCB, true /* wantDuplicates */);
    scan->setActiveScan(true);
    scan->setInterval(45);
    scan->setWindow(30);

    windowCount = 0;
    totalCount  = 0;
    baselinePPS = 0.0f;
    baselineReady = false;
    lowWindows  = 0;
    startTime   = millis();
    windowStart = startTime;

    // Continuous scan; some versions only accept (duration, isContinue)
    scan->start(0, false);
  }

  void stop() {
    if (scan && scan->isScanning()) scan->stop();
  }

  void tick() {
    unsigned long now = millis();
    if (now - windowStart < WINDOW_MS) return;

    float secs = (float)(now - windowStart) / 1000.0f;
    float pps  = windowCount / (secs > 0 ? secs : 1.0f);
    windowCount = 0;
    windowStart = now;

    if (!baselineReady) {
      if (now - startTime >= WARMUP_MS && totalCount >= MIN_BASELINE_COUNT) {
        float elapsed = (float)(now - startTime) / 1000.0f;
        baselinePPS = totalCount / (elapsed > 0 ? elapsed : 1.0f);
        if (baselinePPS < MIN_BASELINE_PPS) baselinePPS = MIN_BASELINE_PPS;
        baselineReady = true;
      }
      return;
    }

    float thresh = baselinePPS * LOW_RATIO;
    if (pps < thresh) lowWindows++; else lowWindows = 0;

    if (lowWindows >= LOW_WINDOWS_TO_ALERT) {
      bleJamDetected = true;
      lastBleJamTime = now;
      lowWindows = 0;
    }
  }
}

// ── ROGUE-AP TRACKING ──
#define MAX_APS             20
#define MAX_BSSIDS_PER_SSID 5
struct APInfo {
  char ssid[33];
  uint8_t bssids[MAX_BSSIDS_PER_SSID][6];
  int bssidCount;
  uint16_t channelsSeen;
  int newChannelCount;
  unsigned long firstDetectTime;
};
APInfo apList[MAX_APS];
int   apCount = 0;

// ── ARP-SPOOF TRACKING ──
#define MAX_ARP_ENTRIES   20
#define MAX_MACS_PER_IP   3
struct ARPInfo {
  uint32_t ip;
  uint8_t macs[MAX_MACS_PER_IP][6];
  int macCount;
};
ARPInfo arpList[MAX_ARP_ENTRIES];
int     arpCount = 0;

// ── BEACON COUNTERS ──
struct BeaconInfo {
  char ssid[33];
  unsigned int count;
  unsigned long windowStart;
};
#define MAX_BEACON_SSIDS 20
BeaconInfo beaconList[MAX_BEACON_SSIDS];
int        beaconCount = 0;

// ── PERSISTENCE ──
Preferences prefs;
void saveAPList() {
  prefs.putUInt("apCount", apCount);
  for (int i = 0; i < apCount; i++) {
    String kS = String("ssid") + i;
    String kC = String("chm")  + i;
    prefs.putString(kS.c_str(), apList[i].ssid);
    prefs.putUInt(  kC.c_str(), apList[i].channelsSeen);
  }
}
void loadAPList() {
  apCount = prefs.getUInt("apCount", 0);
  for (int i = 0; i < apCount && i < MAX_APS; i++) {
    String kS = String("ssid") + i;
    String kC = String("chm")  + i;
    String ss = prefs.getString(kS.c_str(), "");
    ss.toCharArray(apList[i].ssid, 33);
    apList[i].channelsSeen = prefs.getUInt(kC.c_str(), 0);
    apList[i].newChannelCount = 0;
    apList[i].firstDetectTime = 0;
    apList[i].bssidCount      = 0;
  }
}

// ── PUPIL ANIMATION ──
static const int NUM_FRAMES = 4;
static const int offX[NUM_FRAMES] = { 0, 4, 0, -4 };
static const int offY[NUM_FRAMES] = { -4,0,4,  0 };

// ── FACE DRAWING ──
void showHappyFaceAnimated(int f) {
  display.clearDisplay();
  display.fillCircle(64,32,32,WHITE);
  display.fillCircle(32,10,12,BLACK);
  display.fillCircle(96,10,12,BLACK);
  display.fillCircle(46,28,12,BLACK);
  display.fillCircle(82,28,12,BLACK);
  int lx = 46 + offX[f], ly = 28 + offY[f];
  int rx = 82 + offX[f], ry = 28 + offY[f];
  display.fillCircle(lx,ly,3,WHITE);
  display.fillCircle(rx,ry,3,WHITE);
  display.fillCircle(64,44,16,WHITE);
  display.drawCircle(64,44,16,BLACK);
  display.fillCircle(64,40,5,BLACK);
  display.drawLine(56,50,60,54,BLACK);
  display.drawLine(60,54,68,54,BLACK);
  display.drawLine(68,54,72,50,BLACK);
  display.display();
}
void showSadFace() {
  display.clearDisplay();
  display.fillCircle(64,32,32,WHITE);
  display.fillCircle(32,10,12,BLACK);
  display.fillCircle(96,10,12,BLACK);
  display.fillCircle(46,28,12,BLACK);
  display.fillCircle(82,28,12,BLACK);
  display.fillCircle(46,28,3,WHITE);
  display.fillCircle(82,28,3,WHITE);
  display.fillCircle(64,44,16,WHITE);
  display.drawCircle(64,44,16,BLACK);
  display.fillCircle(64,40,5,BLACK);
  display.drawLine(56,54,60,50,BLACK);
  display.drawLine(60,50,68,50,BLACK);
  display.drawLine(68,50,72,54,BLACK);
  display.display();
}

// ── DRAW MENUS ──
void drawMain() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  for (int i = 0; i < MAIN_COUNT; i++) {
    display.setCursor(0, i*10);
    display.print(i == mainIndex ? "> " : "  ");
    display.print(mainItems[i]);
  }
  display.display();
}
void drawSub() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  const char** items = inWifiSub ? wifiItems : btItems;
  for (int i = 0; i < SUB_COUNT; i++) {
    display.setCursor(0, i*10);
    display.print(i == subIndex ? "> " : "  ");
    display.print(items[i]);
  }
  display.display();
}

// ── PACKET HANDLER (Wi-Fi) ──
void IRAM_ATTR packetHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (mode < MODE_DEAUTH || mode > MODE_BEACON) return;
  auto* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* d = pkt->payload;
  unsigned long now = millis();

  if (mode == MODE_DEAUTH && (d[0] & 0xFC) == 0xC0) {
    lastDeauthTime = now; deauthDetected = true;
  }
  if (mode == MODE_ROGUE && (d[0] & 0xF0) == 0x80) {
    uint8_t* bssid = d + 10;
    int off = 36, len = d[off+1]; if (len > 32) len = 32;
    char ssid[33]; memcpy(ssid, d+off+2, len); ssid[len] = 0;
    int idx = -1;
    for (int i = 0; i < apCount; i++)
      if (!strcmp(apList[i].ssid, ssid)) { idx = i; break; }
    if (idx < 0 && apCount < MAX_APS) {
      idx = apCount++;
      strcpy(apList[idx].ssid, ssid);
      memcpy(apList[idx].bssids[0], bssid, 6);
      apList[idx].bssidCount = 1;
      apList[idx].channelsSeen = 1 << currentChannel;
      apList[idx].newChannelCount = 0;
      apList[idx].firstDetectTime = 0;
      saveAPList();
    } else {
      uint16_t mask = 1 << currentChannel;
      if (!(apList[idx].channelsSeen & mask)) {
        apList[idx].channelsSeen |= mask;
        if (apList[idx].firstDetectTime == 0 ||
            now - apList[idx].firstDetectTime > NEW_CHANNEL_WINDOW) {
          apList[idx].firstDetectTime = now;
          apList[idx].newChannelCount = 1;
        } else {
          apList[idx].newChannelCount++;
        }
        if (apList[idx].newChannelCount >= NEW_CHANNEL_THRESHOLD) {
          bool allowed = false;
          for (int k = 0; k < NUM_WHITELIST_OUIS; k++) {
            if (bssid[0]==whitelistOUI[k][0] &&
                bssid[1]==whitelistOUI[k][1] &&
                bssid[2]==whitelistOUI[k][2]) {
              allowed = true; break;
            }
          }
          if (!allowed) { rogueDetected = true; lastRogueTime = now; }
          apList[idx].newChannelCount = 0;
          apList[idx].firstDetectTime = 0;
        }
        saveAPList();
      }
    }
  }
  if (mode == MODE_ARP && type == WIFI_PKT_DATA) {
    int hdr = 24 + ((d[0] & 0x08) ? 4 : 0);
    uint8_t* llc = d + hdr;
    if (llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
        llc[6]==0x08 && llc[7]==0x06) {
      uint8_t* arp = llc + 8;
      if (((arp[6]<<8)|arp[7]) == 2) {
        uint32_t sip; memcpy(&sip, arp+14, 4);
        uint8_t smac[6]; memcpy(smac, arp+8, 6);
        int aidx = -1;
        for (int i = 0; i < arpCount; i++)
          if (arpList[i].ip == sip) { aidx = i; break; }
        if (aidx < 0 && arpCount < MAX_ARP_ENTRIES) {
          aidx = arpCount++;
          arpList[aidx].ip = sip;
          memcpy(arpList[aidx].macs[0], smac, 6);
          arpList[aidx].macCount = 1;
          arpDetected = true; lastARPTime = now;
        } else {
          bool seen = false;
          for (int j = 0; j < arpList[aidx].macCount; j++)
            if (!memcmp(arpList[aidx].macs[j], smac, 6)) { seen = true; break; }
          if (!seen && arpList[aidx].macCount < MAX_MACS_PER_IP) {
            memcpy(arpList[aidx].macs[arpList[aidx].macCount++], smac, 6);
            arpDetected = true; lastARPTime = now;
          }
        }
      }
    }
  }
  if (mode == MODE_BEACON && (d[0]&0xF0)==0x80 && (d[0]&0x0F)==0x08) {
    int off = 36, len = d[off+1]; if (len>32) len=32;
    char ssid[33]; memcpy(ssid, d+off+2, len); ssid[len]=0;
    int idx = -1;
    for (int i = 0; i < beaconCount; i++)
      if (!strcmp(beaconList[i].ssid, ssid)) { idx = i; break; }
    if (idx < 0 && beaconCount < MAX_BEACON_SSIDS) {
      idx = beaconCount++;
      strcpy(beaconList[idx].ssid, ssid);
      beaconList[idx].count = 0;
      beaconList[idx].windowStart = now;
    }
    if (now - beaconList[idx].windowStart > BEACON_WINDOW_MS) {
      beaconList[idx].count = 1;
      beaconList[idx].windowStart = now;
    } else {
      beaconList[idx].count++;
    }
    if (beaconList[idx].count >= BEACON_THRESHOLD) {
      beaconDetected = true; lastBeaconTime = now;
      beaconList[idx].count = 0;
    }
  }
}

// ── SETUP ──
void setup() {
  Serial.begin(115200);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();

  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(GREEN_LED_PIN, HIGH);

  prefs.begin("apstore", false);
  loadAPList();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                   WIFI_PROMIS_FILTER_MASK_DATA
  };
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&packetHandler);
  esp_wifi_set_promiscuous(false);

  drawMain();
}

// ── LOOP ──
void loop() {
  unsigned long now = millis();
  bool raw = digitalRead(BUTTON_PIN);

  if (raw != lastRaw) lastDebounce = now;
  if (now - lastDebounce > DEBOUNCE_DELAY) {
    if (raw == LOW && pressStart == 0) pressStart = now;
    if (raw == HIGH && pressStart > 0) {
      unsigned long held = now - pressStart;
      if (menuLevel == MAIN) {
        if (held < LONG_PRESS_TIME) { mainIndex = (mainIndex + 1) % MAIN_COUNT; drawMain(); }
        else { inWifiSub = (mainIndex == 0); subIndex = 0; menuLevel = SUBMENU; drawSub(); }
      } else if (menuLevel == SUBMENU) {
        if (held < LONG_PRESS_TIME) { subIndex = (subIndex + 1) % SUB_COUNT; drawSub(); }
        else {
          if (subIndex == SUB_COUNT - 1) { menuLevel = MAIN; drawMain(); }
          else {
            if (inWifiSub) {
              mode = Mode(MODE_DEAUTH + subIndex);
              esp_wifi_set_promiscuous(true);
            } else {
              mode = Mode(MODE_BT0 + subIndex);
              // Switching to BLE: stop Wi-Fi promiscuous
              esp_wifi_set_promiscuous(false);
              if (mode == MODE_BT3) {
                BLEJAM::start();  // start BLE Jam Detector
              }
            }
            menuLevel = ACTIVE;
          }
        }
      } else if (menuLevel == ACTIVE) {
        if (held >= LONG_PRESS_TIME) {
          if (mode >= MODE_BT0 && mode <= MODE_BT3) BLEJAM::stop();
          else esp_wifi_set_promiscuous(false);
          mode = MODE_NONE; menuLevel = MAIN; drawMain();
        }
      }
      pressStart = 0;
    }
  }
  lastRaw = raw;

  if (menuLevel == ACTIVE) {
    if (mode >= MODE_DEAUTH && mode <= MODE_BEACON) {
      if (now - lastChannelHop > CHANNEL_HOP_INTERVAL) {
        lastChannelHop = now;
        currentChannel = (currentChannel % 13) + 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      }
      if (deauthDetected && now - lastDeauthTime > ALERT_DURATION) deauthDetected = false;
      if (rogueDetected  && now - lastRogueTime  > ROGUE_TIMEOUT)  rogueDetected  = false;
      if (arpDetected    && now - lastARPTime    > ARP_TIMEOUT)    arpDetected    = false;
      if (beaconDetected && now - lastBeaconTime > ALERT_DURATION) beaconDetected = false;
    } else if (mode == MODE_BT3) {
      BLEJAM::tick();
      if (bleJamDetected && now - lastBleJamTime > ALERT_DURATION) bleJamDetected = false;
    }

    bool alarm = deauthDetected || rogueDetected || arpDetected || beaconDetected || bleJamDetected;

    digitalWrite(RED_LED_PIN,   alarm ? HIGH : LOW);
    digitalWrite(GREEN_LED_PIN, alarm ? LOW  : HIGH);
    digitalWrite(BUZZER_PIN,    alarm ? HIGH : LOW);

    if (alarm) showSadFace();
    else {
      static unsigned long lastAnim = 0; static int frame = 0;
      if (now - lastAnim >= 3000) { lastAnim = now; frame = (frame + 1) % NUM_FRAMES; }
      showHappyFaceAnimated(frame);
    }
    delay(50);
  }
}