/*
  PandaFense — Wi-Fi & BLE Threat Detectors + OLED UI + WebUI
  - One-button UI:
      * Short press   → move cursor
      * Long press    → select / back
  - Menus:
      * Wi-Fi Defense: 14 detectors (select one at a time)
      * Bluetooth Defense: 10 BLE detectors + BLE Jam (select one at a time)
      * Dashboard: prompt to enable AP + Web server
      * Settings: Sound toggle
      * RF Tools: Sub-GHz band tools (band scan, monitor, waterfall, OOK/2-FSK capture, IDS, presets)
  - Display:
      * Idle = happy panda with orbiting pupils
      * Alarm = X-eyes + animated tongue
  - WebUI:
      * HTTP + WebSocket on port 80
      * GET  /api/status
      * POST /api/cmd?action=set&detector=NAME&state=start|stop
      * WS   /ws (pushes status + alert messages)
      * GET  /rf/status      (RF status)
      * POST /rf/set         (tune RF parameters)
      * POST /rf/preset      (apply RF preset)
      * GET  /rf/files       (list RF capture files)
      * GET  /rf/download    (download capture file)
      * Serves / from SPIFFS /index.html (if present) else embedded page
      * mDNS: http://pandafense.local
      * SoftAP fallback: SSID Pandafense-AP / pass pandapass
*/

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <Arduino.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <string.h>
#include <SPI.h>
#include <ELECHOUSE_CC1101_SRC_DRV.h>
// Additional includes for extended honeypot functionality
#include <AsyncUDP.h>            // UDP-based DNS catcher
#include <NimBLEAddress.h>       // For peer address in GAP handler
// Additional NimBLE includes for beacon honeypot support.  NimBLEDevice.h
// already provides scanning support used by the detectors; however, the
// beacon honeypot also needs server and advertising classes.  Pull in
// these headers explicitly to ensure the compiler knows about the
// NimBLEServer, NimBLEAdvertising, and NimBLEConnInfo types.  These
// includes are part of the NimBLE-Arduino library and do not conflict
// with the existing scanning code.
#include <NimBLEServer.h>
#include <NimBLEAdvertising.h>

// ---- WebUI deps ----
#include <SPIFFS.h>
#include <ESPmDNS.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
// Filesystem include needed for honeypot logging
#include <FS.h>
// Additional dependency for DNS-based honeypot modules
#include <DNSServer.h>

// ============================================================================
// Hardware
// ============================================================================
#define BUTTON_PIN        14
#define RED_LED_PIN        2
#define GREEN_LED_PIN     26
#define BUZZER_PIN        18
#define RF_CS_PIN     5
#define RF_GDO0_PIN   4
#define RF_SCK_PIN   25
#define RF_MISO_PIN  27
#define RF_MOSI_PIN  33

// ============================================================================
// OLED Display
// ============================================================================
#define SCREEN_WIDTH     128
#define SCREEN_HEIGHT     64
#define OLED_RESET        -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// Menu text rendering window (scrollable submenu)
static const int ROW_H      = 10;                       // line height
static const int LIST_ROWS  = SCREEN_HEIGHT / ROW_H;    // 6 visible lines
static int       topRow     = 0;                        // first visible item

// ============================================================================
// Menu Model
// ============================================================================
enum MenuLevel { MAIN = 0, SUBMENU = 1, ACTIVE = 2 };
static MenuLevel menuLevel = MAIN;

// Main menu now has Dashboard + Settings + RF Tools
// Added Honeypots to the main menu.  The array length must match MAIN_COUNT.
static const char* mainItems[] = { "Wi-Fi", "Bluetooth", "Dashboard", "Settings", "RF", "Honeypots" };
static const int   MAIN_COUNT  = 6;
static int         mainIndex   = 0;

static int  subIndex  = 0;

// Which submenu we are in
static bool inWifiSub     = true;
static bool inSettingsSub = false;
static bool inDashPrompt  = false;   // NEW: Dashboard prompt active?
static bool inRFSub       = false;   // NEW: RF submenu active?
static bool inRFSettings  = false;   // NEW: RF preset/tuning view?
// NEW: Honeypots submenu active?
static bool inHoneypotsSub = false;

// Settings (persisted)
static bool soundOff = false;  // true = buzzer muted
// Overlay/panda UI toggle (persisted). When true, the animated panda is hidden
// and textual alerts are shown on the OLED instead.
static bool overlayOff = false;

// Last alert details for textual display when overlay is off. These are updated
// whenever pushAlert() is invoked.
static String lastAlertName;
static String lastAlertSev;
static String lastAlertDetail;
static unsigned long lastAlertTs = 0;

// Duration (ms) to continue displaying the last alert after the alarm clears.
static const unsigned long ALERT_TEXT_DURATION = 6000;

// Wi-Fi submenu (14 detectors + "Menu")
static const int WIFI_SUB_COUNT = 15;
static const char* wifiItems[WIFI_SUB_COUNT] = {
  "Deauth Detector",        // 0
  "Rogue AP Detector",      // 1
  "ARP Spoof Detector",     // 2
  "Beacon-Flood Detector",  // 3
  "Disassoc Flood",         // 4
  "Probe Flood",            // 5
  "RTS/CTS Flood",          // 6
  "EAPOL Storm",            // 7
  "CSA Attack",             // 8
  "Spoofed Mgmt",           // 9
  "Beacon Anomaly",         // 10
  "WPS Spam",               // 11
  "RSN Mismatch",           // 12
  "Broadcast Data",         // 13
  "Menu"                    // 14 (back)
};

// Bluetooth submenu (10 scan-only detectors + Jam + Menu)
static const int BT_SUB_COUNT = 12;
static const char* btItems[BT_SUB_COUNT] = {
  "ADV Flood / Device",     // 0
  "Beacon/UUID Flood",      // 1
  "Addr-Hop Impersonation", // 2
  "Service-Set Spoofing",   // 3
  "Mfr-ID Storm",           // 4
  "Scan-Response Abuse",    // 5
  "Interval Anomaly",       // 6
  "Replay/Clone Payload",   // 7
  "Name-Squatting",         // 8
  "RSSI Teleport/Relay",    // 9
  "BLE Jam Detector",       // 10
  "Menu"                    // 11 (back)
};

// RF submenu (6 detectors + preset/tuning + back)
static const int RF_SUB_COUNT = 8;
static const char* rfItems[RF_SUB_COUNT] = {
  "Band Scan",         // 0
  "Monitor @Freq",     // 1
  "Waterfall",         // 2
  "OOK Edge Capture",  // 3
  "2-FSK Capture",     // 4
  "RF IDS (Jam/Flood)",// 5
  "Presets / Tuning",  // 6
  "Menu"               // 7 (back)
};

// Honeypots submenu (3 honeypots + Menu).  These names correspond
// to the deception modules implemented below.  The last entry is a
// "Menu" back item.
// Extend the honeypots submenu to include a BLE beacon honeypot.  The
// additional entry appears before the "Menu" back item.  When adding
// entries here, remember to update HP_SUB_COUNT accordingly and map
// subIndex values in the loop below.
static const int HP_SUB_COUNT = 5;
static const char* hpItems[HP_SUB_COUNT] = {
  "Fake AP Honeypot",     // 0
  "Telnet/SSH Honeypot",  // 1
  "Credential Honeypot",  // 2
  "BLE Beacon Honeypot",  // 3
  "Menu"                  // 4 (back)
};

// ============================================================================
// Modes (keep Wi-Fi block contiguous to map indexes directly)
// ============================================================================
enum Mode {
  MODE_NONE = 0,

  // ---- Wi-Fi detectors (order MUST match wifiItems) ----
  MODE_DEAUTH        = 1,
  MODE_ROGUE         = 2,
  MODE_ARP           = 3,
  MODE_BEACON        = 4,
  MODE_DISASSOC      = 5,
  MODE_PROBE         = 6,
  MODE_RTSCTS        = 7,
  MODE_EAPOL         = 8,
  MODE_CSA           = 9,
  MODE_SPOOFEDMGMT   = 10,
  MODE_BEACON_ANOM   = 11,
  MODE_WPS           = 12,
  MODE_RSN_MISMATCH  = 13,
  MODE_BCAST_DATA    = 14,

  // ---- BLE detectors (order MUST match btItems) ----
  MODE_BT_ADV_FLOOD     = 15, // 0
  MODE_BT_UUID_FLOOD    = 16, // 1
  MODE_BT_ADDR_HOP      = 17, // 2
  MODE_BT_SERVICE_SPOOF = 18, // 3
  MODE_BT_MFR_STORM     = 19, // 4
  MODE_BT_SCANRSP_ABUSE = 20, // 5
  MODE_BT_INTERVAL_ANOM = 21, // 6
  MODE_BT_REPLAY_CLONE  = 22, // 7
  MODE_BT_NAME_SQUAT    = 23, // 8
  MODE_BT_RSSI_TELEPORT = 24, // 9
  MODE_BT_JAM           = 25, // 10

  // ---- RF / Sub-GHz (CC1101) ----
  MODE_RF_BANDSCAN     = 26,
  MODE_RF_MONITOR      = 27,
  MODE_RF_WATERFALL    = 28,
  MODE_RF_OOK_CAPTURE  = 29,
  MODE_RF_2FSK_CAPTURE = 30,
  MODE_RF_IDS          = 31,
  // ---- Honeypot modes ----
  MODE_HP_FAKE_AP      = 32,
  MODE_HP_TELNET       = 33,
  MODE_HP_CREDENTIAL   = 34,
  MODE_HP_BLE_BEACON   = 35
};
static Mode mode = MODE_NONE;

// ============================================================================
// WebUI config + server globals
// ============================================================================
static const char* WIFI_SSID = "SSID"; //Input your Wi-Fi SSID
static const char* WIFI_PASS = "PASSWORD"; //Input your Wi-Fi Password
static const char* MDNS_NAME = "pandafense";           // http://pandafense.local
static const char* TOKEN     = "panda_token_123";      // change me

static bool wifiReady = false;
static bool apMode    = false;
String deviceId = "panda-01";

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

// ---- Dashboard gating (NEW) ----
static bool serverStarted = false;     // HTTP server has been started
static void startDashboard();          // forward declaration

// forward decls for web helpers
static void pushStatus();
static void pushAlert(const String& det, const String& sev, const String& kvpairs);
static String modeName();
static void stopAllDetectors();
static void startDetectorByName(const String& det);

// ======================================================================
// Honeypot globals and helpers
// ======================================================================

// --- Honeypot alert glue ---
// When a honeypot detects a connection, probe, or captured credential, we
// want the device to alert just like the Wi‑Fi/BLE/RF detectors.  These
// globals track whether a honeypot alert is active and when it started.
static bool hpAlert = false;
static unsigned long hpAlertAt = 0;

// helper: push a WS/OLED alert and mark the honeypot alert window.  This
// uses the existing pushAlert() API so that WebUI clients receive
// structured alert objects.  Severity can be "LOW", "MEDIUM" or
// "HIGH" depending on the event.  The kvpairs string should contain
// JSON key/value pairs without surrounding braces.  For example:
//   hpPush("HP_AP", "LOW", "\"event\":\"STA_CONNECT\",\"mac\":\"01:02:03:04:05:06\"");
static inline void hpPush(const char* det, const char* sev, const String& kvpairs) {
  hpAlert = true;
  hpAlertAt = millis();
  pushAlert(String(det), String(sev), kvpairs);
}

// Mask the middle of a string to avoid revealing full usernames in WS
// alerts.  Keeps the first and last character and replaces the rest
// with asterisks.  If the string is two characters or shorter,
// returns a single asterisk.
static String maskMid(const String& s) {
  if (s.length() <= 2) return String("*");
  String out = s;
  for (size_t i = 1; i + 1 < out.length(); ++i) out.setCharAt(i, '*');
  return out;
}

// ------------------------------------------------------------------------
// Additional helpers for honeypot device identification
//
// Convert a MAC address array to a human readable string.  This helper
// duplicates macStr() but provides a clearer name for calls where
// readability matters.  macStr() remains the canonical conversion.
static String fmtMac(const uint8_t m[6]) {
  return macStr(m);
}

// Return the three‑byte OUI portion of a MAC address as a hex string.
// This can be used to derive vendor information or for display.
static String macOUI(const uint8_t m[6]) {
  char buf[7];
  snprintf(buf, sizeof(buf), "%02X%02X%02X", m[0], m[1], m[2]);
  return String(buf);
}

// Quote a string for JSON by escaping backslashes and double quotes.  This
// helper produces a new string wrapped in double quotes.  It is used
// when building JSON fragments for hpPush() to avoid broken payloads.
static String q(const String& s) {
  String t = s;
  t.replace("\\", "\\\\");
  t.replace("\"", "\\\"");
  return String("\"") + t + "\"";
}

// ------------------------------------------------------------------------
// HTTP logging and alerting
//
// hpLogHttp() logs HTTP request details (IP, host, path, UA, language)
// via logEvent() and raises a low severity honeypot alert via hpPush().
// Use this helper in place of logHttp() when honeypot alerting is
// desired.  The alert includes the IP address, request path and basic
// header information.  See hdr() for header retrieval.
static void hpLogHttp(AsyncWebServerRequest* request, const String& path) {
  String ip   = request->client()->remoteIP().toString();
  String ua   = hdr(request, "User-Agent");
  String lang = hdr(request, "Accept-Language");
  String host = request->host();
  // Log to SPIFFS/Serial for forensics
  logEvent(String("HTTP,") + ip + ",HOST:" + host + ",PATH:" + path + ",UA:" + ua + ",LANG:" + lang);
  // Raise a low severity HTTP honeypot alert with basic info
  String kv = String("\"ip\":") + q(ip) + ",\"path\":" + q(path) +
               ",\"ua\":" + q(ua) + ",\"lang\":" + q(lang) + ",\"host\":" + q(host);
  hpPush("HONEYPOT_HTTP", "LOW", kv);
}

// ------------------------------------------------------------------------
// OUI vendor lookup for MAC addresses
//
// When a station connects to our honeypot AP we can derive its vendor by
// looking up the first three bytes (OUI) of its MAC address.  This small
// table covers common mobile/IoT vendors; unlisted prefixes return "Unknown".
struct OUIMap { uint8_t oui[3]; const char* vendor; };
static const OUIMap OUIS[] PROGMEM = {
  {{0x28,0xCF,0xE9},"Apple"},    {{0xF0,0xD1,0xA9},"Apple"},
  {{0xDC,0xFB,0x48},"Samsung"},  {{0xFC,0xDB,0xB3},"Samsung"},
  {{0x3C,0x5A,0xB4},"Xiaomi"},   {{0x20,0x47,0xDA},"Google"},
  {{0xA4,0x50,0x46},"OnePlus"},  {{0x00,0x1A,0x11},"Cisco"},
  {{0x9C,0x2A,0x70},"AzureWave"},{{0x10,0xAE,0x60},"Espressif"}
};

// Convert a MAC address array to a human readable string
static String macStr(const uint8_t m[6]) {
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(b);
}

// Lookup the vendor name from the first three bytes of a MAC address.
static const char* vendorFromMac(const uint8_t m[6]) {
  for (size_t i = 0; i < sizeof(OUIS) / sizeof(OUIS[0]); ++i) {
    if (m[0] == OUIS[i].oui[0] && m[1] == OUIS[i].oui[1] && m[2] == OUIS[i].oui[2]) {
      return OUIS[i].vendor;
    }
  }
  return "Unknown";
}

// ------------------------------------------------------------------------
// HTTP header extraction and logging
//
// To profile connecting devices, we log key HTTP headers such as User-Agent,
// Accept-Language and Host.  These helpers fetch header values and emit
// them to SPIFFS via logEvent().  They are used by both the fake AP and
// credential honeypot servers.

// Return the value of a named header if present, otherwise an empty string.
static String hdr(AsyncWebServerRequest* r, const String& name) {
  return r->hasHeader(name) ? r->getHeader(name)->value() : String();
}

// Log HTTP request details (IP, host, path, UA and language) for later analysis.
static void logHttp(AsyncWebServerRequest* request, const String& path) {
  String ua   = hdr(request, "User-Agent");
  String lang = hdr(request, "Accept-Language");
  String host = request->host();
  String ip   = request->client()->remoteIP().toString();
  logEvent(String("HTTP,") + ip + ",HOST:" + host + ",PATH:" + path + ",UA:" + ua + ",LANG:" + lang);
}

// ------------------------------------------------------------------------
// DNS catcher via AsyncUDP
//
// The captive portal relies on DNS redirection to force devices onto our AP.
// Instead of DNSServer (which doesn't expose query names), we use AsyncUDP
// to capture the QNAME, log it and answer all queries with the AP IP.  The
// parseQName helper decodes a DNS question name from a raw packet.

static AsyncUDP dnsUDP;

// Decode a DNS QNAME (labels separated by length bytes) from a packet.
// Updates off to the byte after the name.  Returns the assembled domain.
static String parseQName(const uint8_t* p, size_t len, size_t& off) {
  String name;
  size_t i = off;
  while (i < len) {
    uint8_t l = p[i++];
    if (!l) break;                 // zero length terminator
    if ((l & 0xC0) == 0xC0) {      // compression pointer
      if (i < len) i++;            // skip pointer byte
      break;
    }
    if (i + l > len) break;        // truncated label
    if (name.length()) name += ".";
    name += String((const char*)p + i).substring(0, l);
    i += l;
  }
  off = i;
  return name;
}

// Start a UDP listener on port 53 that logs each query name and responds
// with an A record pointing at apIP.  This replaces the DNSServer used
// previously and provides visibility into which domains clients request.
static void startDnsCatcher(IPAddress apIP) {
  dnsUDP.listen(53);
  dnsUDP.onPacket([apIP](AsyncUDPPacket p){
    const uint8_t* d = p.data();
    size_t n = p.length();
    if (n < 12) return;
    uint16_t id = (d[0] << 8) | d[1];
    (void)id; // unused
    size_t off = 12;
    String qname = parseQName(d, n, off);
    if (qname.length()) {
      logEvent(String("DNS,") + p.remoteIP().toString() + ",Q:" + qname);
    }
    // Build a minimal DNS response: copy header, set flags and ANCOUNT=1
    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));
    memcpy(resp, d, 12);
    resp[2] = 0x81; resp[3] = 0x80; // standard response with no error
    resp[7] = 0x01;                // ANCOUNT = 1
    size_t w = 12;
    memcpy(resp + w, d + 12, n - 12); // copy the question section
    w += (n - 12);
    // Answer: pointer to name at 0x0c, type A, class IN, TTL=30, RDLEN=4, RDATA=apIP
    resp[w++] = 0xC0; resp[w++] = 0x0C;
    resp[w++] = 0x00; resp[w++] = 0x01; // TYPE A
    resp[w++] = 0x00; resp[w++] = 0x01; // CLASS IN
    resp[w++] = 0x00; resp[w++] = 0x00; resp[w++] = 0x00; resp[w++] = 0x1E; // TTL = 30 sec
    resp[w++] = 0x00; resp[w++] = 0x04; // RDLEN = 4 bytes
    resp[w++] = apIP[0]; resp[w++] = apIP[1]; resp[w++] = apIP[2]; resp[w++] = apIP[3];
    p.write(resp, w);
  });
}

// ------------------------------------------------------------------------
// NimBLE GAP event handler
//
// Some platforms randomize BLE MAC addresses, but the GAP connect event
// still carries useful parameters such as address type, connection
// interval/latency and supervision timeout.  This handler logs those
// details and raises a low‑severity honeypot BLE alert.
static int onGapEvent(struct ble_gap_event* ev, void* arg) {
  (void)arg;
  // In this implementation we do not access the peer address or connection
  // parameters directly because the ble_gap_event structure varies across
  // NimBLE versions.  Instead we simply note the occurrence of the
  // connection or disconnection and raise a generic BLE honeypot alert.
  if (ev->type == BLE_GAP_EVENT_CONNECT) {
    logEvent("BLE_CONNECT");
    hpPush("HONEYPOT_BLE", "LOW", String("\"event\":\"connect\""));
  } else if (ev->type == BLE_GAP_EVENT_DISCONNECT) {
    logEvent(String("BLE_DISCONNECT"));
  }
  return 0;
}


// DNS server used for fake AP and credential honeypots
static DNSServer dnsServer;
// HTTP servers for fake AP and credential honeypots (separate ports to avoid conflict with main WebUI)
static AsyncWebServer fakeApServer(8080);
static AsyncWebServer credentialServer(8081);
// Telnet/SSH servers for honeypot
static WiFiServer telnetServer(23);
static WiFiServer sshServer(22);

// Session state for Telnet/SSH honeypot
struct SessionState {
  WiFiClient client;
  bool authenticated;
  bool awaitingUsername;
  bool awaitingPassword;
  String username;
  String password;
  String currentLine;
};
static const int MAX_SESSIONS = 2;
static SessionState sessions[MAX_SESSIONS];

// Simple log helper for honeypot events.  Logs to Serial and SPIFFS.
static const char* HP_LOG_FILE = "/honeypot_events.csv";
static void logEvent(const String& event) {
  // Use millis as a timestamp to avoid RTC dependency
  char timeBuf[16];
  snprintf(timeBuf, sizeof(timeBuf), "%lu", (unsigned long)millis());
  String line = String(timeBuf) + "," + event + "\n";
  Serial.print(line);
  File f = SPIFFS.open(HP_LOG_FILE, FILE_APPEND);
  if (f) {
    f.print(line);
    f.close();
  }
}

// Forward declarations for honeypot setup/maintenance functions
static void setupFakeAPHoneypot(const char* ssid, const char* password, bool captivePortal);
static void maintainFakeAP();
static void setupCredentialHoneypot(const char* ssid);
static void initTelnetHoneypot();
static void handleNewTelnetConnections();
static void processTelnetSessions();

// Event handler for SoftAP events.  This callback is registered when a
// honeypot AP is started.  It captures station connections,
// disconnections and probe requests and raises honeypot alerts.
static void onSoftAPEvent(arduino_event_id_t event, arduino_event_info_t info);

// ========================================================================
// BLE beacon honeypot globals and helpers
//
// The beacon honeypot uses the NimBLE library to advertise a BLE service
// and characteristic.  We store pointers to the server, service,
// characteristic and advertising object so we can stop advertising later.
// A flag tracks whether the beacon has been started.
static NimBLEServer*         hpBleServer         = nullptr;
static NimBLEService*        hpBleService        = nullptr;
static NimBLECharacteristic* hpBleCharacteristic = nullptr;
static NimBLEAdvertising*    hpBleAdvertising    = nullptr;
static bool                  hpBleStarted        = false;

// UUIDs for the beacon service and characteristic.  These values match
// those used in the original beacon honeypot and can be changed if
// desired.  They must remain globally visible because they are passed
// directly into NimBLE APIs.
static const char* BLE_HP_SERVICE_UUID        = "12345678-1234-1234-1234-1234567890ab";
static const char* BLE_HP_CHARACTERISTIC_UUID = "87654321-4321-4321-4321-ba0987654321";

// Callback class for the beacon honeypot.  Overrides the NimBLE server
// callbacks to log client connections and disconnections.  When a
// client disconnects, advertising is restarted so the beacon remains
// discoverable.
class HoneypotBLEServerCallbacks : public NimBLEServerCallbacks {
public:
  // Handle BLE connection with NimBLEConnInfo.  When a peer connects
  // this callback provides an object from which the peer address can
  // be obtained.  Use this to log the connection and raise a low
  // severity honeypot alert.  Note: The base class defines this
  // signature; there is no zero‑argument onConnect nor a ble_gap_conn_desc
  // variant in the Arduino NimBLE API.
  void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
    NimBLEAddress addr = connInfo.getAddress();
    String mac = String(addr.toString().c_str());
    logEvent(String("BLE_CLIENT_CONNECTED,") + mac);
    // Raise a low severity honeypot alert for BLE connection
    String kv = String("\"event\":\"connect\",\"mac\":") + q(mac);
    hpPush("HP_BLE", "LOW", kv);
  }
  // Handle BLE disconnection.  Restart advertising and raise alert.
  void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
    NimBLEAddress addr = connInfo.getAddress();
    String mac = String(addr.toString().c_str());
    logEvent(String("BLE_CLIENT_DISCONNECTED,") + mac);
    String kv = String("\"event\":\"disconnect\",\"mac\":") + q(mac);
    hpPush("HP_BLE", "LOW", kv);
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (adv) {
      adv->start();
    }
  }
};

// Initialize and start the BLE beacon honeypot.  This function ensures
// NimBLE is initialized (calling setDeviceName if already init), creates
// a server, service and characteristic, and starts advertising the
// service.  A default characteristic value is provided so that clients
// can read something.  Use a unique device name so the beacon is easy
// to identify when scanning.
static void initBleBeaconHoneypot(const char* deviceName) {
  // If NimBLE was already initialized (e.g. scanning was active), do not
  // reinitialize; just update the advertised device name.  Otherwise
  // initialise the NimBLE stack with the provided name.  The device
  // name influences what appears in scanning apps.
  if (!NimBLEDevice::isInitialized()) {
    NimBLEDevice::init(deviceName);
    // Register custom GAP handler on initialisation
    NimBLEDevice::setCustomGapHandler(onGapEvent);
  } else {
    NimBLEDevice::setDeviceName(deviceName);
    // Ensure our GAP handler is registered even if already initialised
    NimBLEDevice::setCustomGapHandler(onGapEvent);
  }
  // Create a server if one does not already exist.
  if (hpBleServer == nullptr) {
    hpBleServer = NimBLEDevice::createServer();
    hpBleServer->setCallbacks(new HoneypotBLEServerCallbacks());
  }
  // Create a service if necessary.
  if (hpBleService == nullptr) {
    hpBleService = hpBleServer->createService(BLE_HP_SERVICE_UUID);
  }
  // Create characteristic if necessary.
  if (hpBleCharacteristic == nullptr) {
    hpBleCharacteristic = hpBleService->createCharacteristic(BLE_HP_CHARACTERISTIC_UUID,
      NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
    hpBleCharacteristic->setValue("PandaFense");
  }
  // Start the service to make characteristic available.
  hpBleService->start();
  // Obtain the advertising object and configure it.
  hpBleAdvertising = NimBLEDevice::getAdvertising();
  // Reset advertising data to defaults.  Clear previous entries.
  hpBleAdvertising->stop();
  hpBleAdvertising->clearData();
  hpBleAdvertising->addServiceUUID(BLE_HP_SERVICE_UUID);
  hpBleAdvertising->setName(deviceName);
  // Start advertising.  Duration 0 means advertise indefinitely until stopped.
  hpBleAdvertising->start();
  hpBleStarted = true;
  logEvent(String("BLE_BEACON_HONEYPOT_STARTED,") + deviceName);
}

// Stop the BLE beacon honeypot.  Advertising is stopped and the NimBLE
// stack remains initialized so that scanning detectors can resume
// operation when needed.  This function is called from stopAllDetectors().
static void stopBleBeaconHoneypot() {
  if (hpBleStarted) {
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (adv) {
      adv->stop();
    }
    hpBleStarted = false;
  }
}

// ------------------------------------------------------------------------
// SoftAP event handler
//
// When running a honeypot in AP mode (fake AP or credential capture), we
// register this callback with WiFi.onEvent().  The callback fires for
// station connections, disconnections and probe requests.  It raises
// honeypot alerts via hpPush().  The event IDs correspond to the
// Arduino‑ESP32 v3.x API.
static void onSoftAPEvent(arduino_event_id_t event, arduino_event_info_t info) {
  switch(event) {
    case ARDUINO_EVENT_WIFI_AP_STACONNECTED: {
      const uint8_t* m = info.wifi_ap_staconnected.mac;
      String macS = macStr(m);
      const char* vendor = vendorFromMac(m);
      logEvent(String("AP_CLIENT_CONNECTED,") + macS + ",VENDOR:" + vendor);
      hpPush("HP_AP", "LOW",
             String("\"event\":\"STA_CONNECT\",\"mac\":\"") + macS +
             "\",\"vendor\":\"" + String(vendor) + "\"");
    } break;
    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED: {
      const uint8_t* m = info.wifi_ap_stadisconnected.mac;
      String macS = macStr(m);
      logEvent(String("AP_CLIENT_DISCONNECTED,") + macS);
      hpPush("HP_AP", "LOW",
             String("\"event\":\"STA_DISCONNECT\",\"mac\":\"") + macS + "\"");
    } break;
    case ARDUINO_EVENT_WIFI_AP_PROBEREQRECVED: {
      const uint8_t* m = info.wifi_ap_probereqrecved.mac;
      String macS = macStr(m);
      const char* vendor = vendorFromMac(m);
      int rssi = info.wifi_ap_probereqrecved.rssi;
      logEvent(String("AP_PROBE_REQUEST,") + macS + ",RSSI:" + String(rssi) + ",VENDOR:" + vendor);
      hpPush("HP_AP", "LOW",
             String("\"event\":\"PROBE_REQ\",\"mac\":\"") + macS +
             "\",\"vendor\":\"" + String(vendor) + "\",\"rssi\":" + String(rssi));
    } break;
    default: break;
  }
}

// Optional: embedded minimal UI (served if no /index.html on SPIFFS)
static const char indexHtml[] PROGMEM = R"HTML(
<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Pandafense WebUI</title>
<style>body{font-family:system-ui;margin:0;background:#0b0f14;color:#e6edf3}
h1{font-size:18px;margin:0} header{padding:12px;background:#0e1720;border-bottom:1px solid #223}
.wrap{padding:12px} button{background:#1f6feb;border:0;color:#fff;padding:8px 10px;border-radius:8px;cursor:pointer}
button.s{background:#2d333b} .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
pre{background:#0e1420;border:1px solid #223;border-radius:8px;padding:8px;max-height:40vh;overflow:auto}
.chip{padding:4px 8px;border:1px solid #345;border-radius:999px} input,select{background:#0e1420;color:#e6edf3;border:1px solid #223;border-radius:8px;padding:8px}
.ok{color:#7ee787}.bad{color:#ffa657}.muted{color:#9da7b3}
</style>
<header><div class=row style="justify-content:space-between;padding:0 12px">
  <h1>Pandafense WebUI</h1><div class=muted id=host></div></div></header>
<div class=wrap>
  <div class=row>
    <div>Device: <b id=dev>—</b></div>
    <div>Wi-Fi: <b id=wf class=muted>checking…</b></div>
    <div>Mode: <b id=mode>NONE</b></div>
  </div>
  <div class=row style=margin-top:8px>
    <select id=det>
      <optgroup label="Wi-Fi">
        <option>DEAUTH</option><option>ROGUE_AP</option><option>ARP</option>
        <option>BEACON</option><option>DISASSOC</option><option>PROBE</option>
        <option>RTSCTS</option><option>EAPOL</option><option>CSA</option>
        <option>SPOOFEDMGMT</option><option>BEACON_ANOM</option><option>WPS</option>
        <option>RSN_MISMATCH</option><option>BCAST_DATA</option>
      </optgroup>
      <optgroup label="BLE">
        <option>BT_ADV_FLOOD</option><option>BT_UUID_FLOOD</option><option>BT_ADDR_HOP</option>
        <option>BT_SERVICE_SPOOF</option><option>BT_MFR_STORM</option><option>BT_SCANRSP_ABUSE</option>
        <option>BT_INTERVAL_ANOM</option><option>BT_REPLAY_CLONE</option><option>BT_NAME_SQUAT</option>
        <option>BT_RSSI_TELEPORT</option><option>BT_JAM</option>
      </optgroup>
      <optgroup label="RF (CC1101)">
        <option>RF_BANDSCAN</option>
        <option>RF_MONITOR</option>
        <option>RF_WATERFALL</option>
        <option>RF_OOK_CAPTURE</option>
        <option>RF_2FSK_CAPTURE</option>
        <option>RF_IDS</option>
      </optgroup>
    </select>
    <button id=start>Start</button><button class=s id=stop>Stop</button>
    <input id=tok placeholder="Token (Bearer)" style="min-width:180px">
  </div>
  <div style=margin-top:8px class=row>
    <button class=s id=refresh>Refresh</button>
    <button class=s id=clear>Clear Log</button>
  </div>
  <pre id=log></pre>
</div>
<script>
const E=(id)=>document.getElementById(id); const log=E('log');
function line(s){log.textContent+=s+"\n"; log.scrollTop=log.scrollHeight;}
function hdr(){const t=E('tok').value.trim();const h={'Content-Type':'application/x-www-form-urlencoded'};if(t)h['Authorization']='Bearer '+t;return h;}
function qp(){const t=E('tok').value.trim();return t?('?token='+encodeURIComponent(t)):"";}
async function status(){try{const r=await fetch('/api/status'+qp(),{headers:hdr()});const j=await r.json();
  E('dev').textContent=j.deviceId||'—'; E('mode').textContent=j.modeName||String(j.mode);
  const wf=j.wifiReady||j.apMode; E('wf').textContent=wf? (j.apMode?'AP':'connected'):'down'; E('wf').className=wf?'ok':'bad';
}catch(e){line('[status] '+e.message);}}
async function cmd(det,on){const body=`action=set&detector=${encodeURIComponent(det)}&state=${on?'start':'stop'}`;
  const r=await fetch('/api/cmd'+qp(),{method:'POST',headers:hdr(),body}); if(!r.ok){line('[cmd] HTTP '+r.status);}}
function openWS(){const p=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(`${p}://${location.host}/ws`);
  ws.onopen=()=>line('[ws] connected'); ws.onclose=()=>{line('[ws] disconnected; retry…'); setTimeout(openWS,1500);};
  ws.onmessage=(ev)=>{try{const m=JSON.parse(ev.data);
    if(m.event==='hello'||m.event==='status'){const j=m.payload; E('dev').textContent=j.deviceId||'—'; E('mode').textContent=j.modeName||String(j.mode);
      const wf=j.wifiReady||j.apMode; E('wf').textContent=wf? (j.apMode?'AP':'connected'):'down'; E('wf').className=wf?'ok':'bad';}
    else if(m.event==='alert'){line('[ALERT] '+JSON.stringify(m.payload));}
  }catch(e){line('[ws] parse '+e.message);}};}
E('start').onclick=()=>cmd(E('det').value,true); E('stop').onclick=()=>cmd(E('det').value,false);
E('refresh').onclick=status; E('clear').onclick=()=>log.textContent='';
E('host').textContent=location.origin; status(); openWS();
</script>
)HTML";

// ============================================================================
// Button Handling (short = move, long = select/back)
// ============================================================================
static bool          lastRaw       = HIGH;
static unsigned long lastDebounce  = 0;
static unsigned long pressStart    = 0;
static const unsigned long DEBOUNCE_DELAY  = 50;
static const unsigned long LONG_PRESS_TIME = 1500;

// ============================================================================
// Timing / Thresholds
// ============================================================================
static const unsigned long CHANNEL_HOP_INTERVAL = 200;     // Wi-Fi hop (ms)
static const unsigned long ALERT_DURATION       = CHANNEL_HOP_INTERVAL * 13 + 500;

static const unsigned long ROGUE_TIMEOUT        = 500;
static const unsigned long ARP_TIMEOUT          = 500;
static const unsigned long DISASSOC_TIMEOUT     = 500;

static const unsigned long BEACON_WINDOW_MS     = 1000;
static const int           BEACON_THRESHOLD     = 100;

static const unsigned long NEW_CHANNEL_WINDOW   = 60000;   // Rogue SSID hop window
static const int           NEW_CHANNEL_THRESHOLD= 3;       // hops before flag

// OLED: tongue animation speed
static const unsigned long TONGUE_ANIM_MS       = 250;

// ============================================================================
// Whitelisting (BSSID OUI) for Rogue AP
// ============================================================================
#define NUM_WHITELIST_OUIS 1
static const uint8_t whitelistOUI[NUM_WHITELIST_OUIS][3] = { {0xAA,0xBB,0xCC} };

// ============================================================================
// Wi-Fi: Detection State
// ============================================================================
static volatile unsigned long lastDeauthTime = 0;    static volatile bool deauthDetected    = false;
static volatile unsigned long lastRogueTime  = 0;    static volatile bool rogueDetected     = false;
static volatile unsigned long lastARPTime    = 0;    static volatile bool arpDetected       = false;
static volatile unsigned long lastBeaconTime = 0;    static volatile bool beaconDetected    = false;

static volatile bool disassocDetected=false;         static volatile unsigned long lastDisassocTime=0;
static volatile bool probeFloodDetected=false;       static volatile unsigned long lastProbeTime=0;
static volatile bool rtsctsDetected=false;           static volatile unsigned long lastRtsCtsTime=0;
static volatile bool eapolStormDetected=false;       static volatile unsigned long lastEapolTime=0;
static volatile bool csaDetected=false;              static volatile unsigned long lastCsaTime=0;
static volatile bool spoofMgmtDetected=false;        static volatile unsigned long lastSpoofTime=0;
static volatile bool beaconAnomDetected=false;       static volatile unsigned long lastBeaconAnomTime=0;
static volatile bool wpsSpamDetected=false;          static volatile unsigned long lastWpsTime=0;
static volatile bool rsnMismatchDetected=false;      static volatile unsigned long lastRsnMismatchTime=0;
static volatile bool bcastDataDetected=false;        static volatile unsigned long lastBcastDataTime=0;

static uint8_t       currentChannel  = 1;
static unsigned long lastChannelHop  = 0;

// ============================================================================
// BLE: Jam Detection (baseline drop heuristic)
// ============================================================================
static volatile bool        bleJamDetected   = false;
static volatile unsigned long lastBleJamTime = 0;

namespace BLEJAM {
  static const uint32_t WINDOW_MS            = 3000;
  static const uint32_t WARMUP_MS            = 15000;
  static const int      LOW_WINDOWS_TO_ALERT = 3;
  static const float    LOW_RATIO            = 0.15f; // below 15% baseline
  static const float    MIN_BASELINE_PPS     = 2.0f;
  static const int      MIN_BASELINE_COUNT   = 60;

  static volatile uint32_t windowCount = 0;
  static volatile uint32_t totalCount  = 0;

  static unsigned long windowStart = 0;
  static unsigned long startTime   = 0;
  static float         baselinePPS = 0.0f;
  static bool          baselineReady = false;
  static int           lowWindows  = 0;

  static NimBLEScan* scan = nullptr;

  class ScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* d) override {
      windowCount++; totalCount++; (void)d;
    }
  } scanCB;

  static void start() {
    static bool inited = false;
    if (!inited) { NimBLEDevice::init(""); inited = true; }
    scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&scanCB, true);
    scan->setActiveScan(true);
    scan->setInterval(45);
    scan->setWindow(30);
    windowCount = 0; totalCount = 0;
    baselinePPS = 0.0f; baselineReady = false;
    lowWindows = 0; startTime = millis(); windowStart = startTime;
    scan->start(0, false); // continuous
  }
  static void stop() { if (scan && scan->isScanning()) scan->stop(); }

  static void tick() {
    unsigned long now = millis();
    if (now - windowStart < WINDOW_MS) return;

    float secs = (float)(now - windowStart) / 1000.0f;
    float pps  = windowCount / (secs > 0 ? secs : 1.0f);
    windowCount = 0; windowStart = now;

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
    lowWindows = (pps < thresh) ? (lowWindows + 1) : 0;
    if (lowWindows >= LOW_WINDOWS_TO_ALERT) {
      bleJamDetected = true; lastBleJamTime = now; lowWindows = 0;
    }
  }
} // namespace BLEJAM

// ============================================================================
// Rogue AP / ARP / Beacon Tracking Tables
// ============================================================================
#define MAX_APS               20
#define MAX_BSSIDS_PER_SSID    5
struct APInfo {
  char ssid[33];
  uint8_t bssids[MAX_BSSIDS_PER_SSID][6];
  int bssidCount;
  uint16_t channelsSeen;
  int newChannelCount;
  unsigned long firstDetectTime;
  bool seenOpen;
  bool seenRSN;
};
static APInfo apList[MAX_APS];
static int    apCount = 0;

#define MAX_ARP_ENTRIES       20
#define MAX_MACS_PER_IP        3
struct ARPInfo {
  uint32_t ip;
  uint8_t  macs[MAX_MACS_PER_IP][6];
  int      macCount;
};
static ARPInfo arpList[MAX_ARP_ENTRIES];
static int     arpCount = 0;

#define MAX_BEACON_SSIDS      20
struct BeaconInfo {
  char ssid[33];
  unsigned int count;
  unsigned long windowStart;
};
static BeaconInfo beaconList[MAX_BEACON_SSIDS];
static int        beaconCount = 0;

// Persist only a sketch of AP list: SSID + channels bitmask
Preferences prefs;
static void saveAPList() {
  prefs.putUInt("apCount", apCount);
  for (int i = 0; i < apCount; i++) {
    String kS = String("ssid") + i;
    String kC = String("chm")  + i;
    prefs.putString(kS.c_str(), apList[i].ssid);
    prefs.putUInt(kC.c_str(), apList[i].channelsSeen);
  }
}
static void loadAPList() {
  apCount = prefs.getUInt("apCount", 0);
  for (int i = 0; i < apCount && i < MAX_APS; i++) {
    String kS = String("ssid") + i;
    String kC = String("chm")  + i;
    String ss = prefs.getString(kS.c_str(), "");
    ss.toCharArray(apList[i].ssid, 33);
    apList[i].channelsSeen    = prefs.getUInt(kC.c_str(), 0);
    apList[i].newChannelCount = 0;
    apList[i].firstDetectTime = 0;
    apList[i].bssidCount      = 0;
    apList[i].seenOpen        = false;
    apList[i].seenRSN         = false;
  }
}

// Save settings helper
static void saveSettings() {
  prefs.putUChar("soundOff", soundOff ? 1 : 0);
  prefs.putUChar("overlayOff", overlayOff ? 1 : 0);
}

// ============================================================================
// Wi-Fi Detector Helpers (probe flood, CSA/WPS, etc.)
// ============================================================================
struct ProbeMacEntry;
struct CountEntry;

static uint16_t ssidSig(const uint8_t* s, int len);
static ProbeMacEntry* getProbeEntry(const uint8_t* mac);
static void resetProbeWindow(void);
static CountEntry* getEntry(CountEntry* arr, int& n, const uint8_t* bssid);
static void resetBssidWindow(CountEntry* arr, int& n, unsigned long& start);

static const unsigned long PROBE_WINDOW_MS = 2000;
static const int           PROBE_PER_MAC_THRESH = 25;
static const int           PROBE_TOTAL_THRESH   = 300;

static const unsigned long RTSCTS_WINDOW_MS   = 3000;
static const int           RTSCTS_COUNT_THRESH = 60;
static const uint16_t      NAV_DUR_US_THRESH   = 20000;
static const int           NAV_HIGH_COUNT_THRESH= 30;

static const unsigned long EAPOL_WINDOW_MS = 5000;
static const int           EAPOL_THRESH    = 20;

static const unsigned long CSA_WINDOW_MS   = 5000;
static const int           CSA_PER_BSSID_THRESH = 10;

static const unsigned long SPOOF_TIMEOUT   = 1500;

static const unsigned long BEACON_ANOM_WINDOW_MS = 5000;
static const int           ZERO_SSID_THRESH = 50;
static const int           BAD_IE_THRESH    = 20;

static const unsigned long WPS_WINDOW_MS = 5000;
static const int           WPS_PER_BSSID_THRESH = 20;

static const unsigned long RSN_MISMATCH_TIMEOUT = 3000;

static const unsigned long BCAST_WINDOW_MS = 2000;
static const int           BCAST_DATA_THRESH = 200;

static inline bool macEq(const uint8_t* a, const uint8_t* b){ return memcmp(a,b,6)==0; }
static inline void macCpy(uint8_t* dst, const uint8_t* src){ memcpy(dst,src,6); }

// Known BSSIDs (for spoofed-mgmt heuristic)
#define MAX_KNOWN_BSSID 40
static uint8_t knownBssids[MAX_KNOWN_BSSID][6]; static int knownBssidCount=0;
static void addKnownBssid(const uint8_t* bssid){
  for(int i=0;i<knownBssidCount;i++) if(macEq(knownBssids[i], bssid)) return;
  if(knownBssidCount < MAX_KNOWN_BSSID) macCpy(knownBssids[knownBssidCount++], bssid);
}
static bool isKnownBssid(const uint8_t* bssid){
  for(int i=0;i<knownBssidCount;i++) if(macEq(knownBssids[i], bssid)) return true;
  return false;
}

// ---- Probe flood tracking ----
#define MAX_PROBE_MACS 20
#define MAX_SIGS_PER_MAC 6
struct ProbeMacEntry {
  uint8_t mac[6];
  int count;
  uint16_t sigs[MAX_SIGS_PER_MAC];
  uint8_t sigCount;
};
static ProbeMacEntry probeMacs[MAX_PROBE_MACS];
static int probeMacCount=0;
static unsigned long probeWindowStart=0;
static int probeTotalCount=0;

static uint16_t ssidSig(const uint8_t* s, int len){
  uint16_t h=0; for(int i=0;i<len;i++) h = (h<<5) ^ (h>>11) ^ s[i]; return h;
}
static ProbeMacEntry* getProbeEntry(const uint8_t* mac){
  for(int i=0;i<probeMacCount;i++) if(macEq(probeMacs[i].mac, mac)) return &probeMacs[i];
  if(probeMacCount < MAX_PROBE_MACS){
    memset(&probeMacs[probeMacCount], 0, sizeof(ProbeMacEntry));
    macCpy(probeMacs[probeMacCount].mac, mac);
    return &probeMacs[probeMacCount++];
  }
  return nullptr;
}
static void resetProbeWindow(void){
  probeWindowStart = millis();
  probeTotalCount = 0;
  for(int i=0;i<probeMacCount;i++){ probeMacs[i].count=0; probeMacs[i].sigCount=0; }
}

// ---- RTS/CTS, EAPOL, CSA/WPS tracking ----
static unsigned long rtsctsWindowStart=0; static int rtsctsCount=0; static int navHighCount=0;
static unsigned long eapolWindowStart=0; static int eapolCount=0;

#define MAX_TRACK_BSSID 30
struct CountEntry { uint8_t bssid[6]; int count; };
static CountEntry csaEntries[MAX_TRACK_BSSID]; static int csaEntryCount=0; static unsigned long csaWindowStart=0;
static CountEntry wpsEntries[MAX_TRACK_BSSID]; static int wpsEntryCount=0; static unsigned long wpsWindowStart=0;

static CountEntry* getEntry(CountEntry* arr, int& n, const uint8_t* bssid){
  for(int i=0;i<n;i++) if(macEq(arr[i].bssid,bssid)) return &arr[i];
  if(n < MAX_TRACK_BSSID){ macCpy(arr[n].bssid,bssid); arr[n].count=0; return &arr[n++]; }
  return nullptr;
}
static void resetBssidWindow(CountEntry* arr, int& n, unsigned long& start){
  start = millis(); for(int i=0;i<n;i++) arr[i].count=0;
}

// ---- Beacon anomaly & broadcast data windows ----
static unsigned long beaconAnomWindowStart=0; static int zeroSsidCount=0; static int badIeCount=0;
static unsigned long bcastWindowStart=0; static int bcastCount=0;

// ============================================================================
// UI — Panda Faces
// ============================================================================
// Idle: pupils orbit
static const int NUM_FRAMES = 4;
static const int offX[NUM_FRAMES] = { 0, 4, 0, -4 };
static const int offY[NUM_FRAMES] = { -4, 0, 4,  0 };

static void showHappyFaceAnimated(int f) {
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
  display.drawLine(56,54,60,54,BLACK);
  display.drawLine(60,54,68,54,BLACK);
  display.drawLine(68,54,72,50,BLACK);
  display.display();
}

// Alarm: X-eyes + flat mouth + animated tongue
static void showDeadFaceAnimated(bool flip) {
  display.clearDisplay();
  display.fillCircle(64,32,32,WHITE);
  display.fillCircle(32,10,12,BLACK);
  display.fillCircle(96,10,12,BLACK);
  display.fillCircle(46,28,12,BLACK);
  display.fillCircle(82,28,12,BLACK);
  display.drawLine(40,22,52,34,WHITE);
  display.drawLine(40,34,52,22,WHITE);
  display.drawLine(76,22,88,34,WHITE);
  display.drawLine(76,34,88,22,WHITE);
  display.fillCircle(64,44,16,WHITE);
  display.drawCircle(64,44,16,BLACK);
  display.fillCircle(64,40,5,BLACK);
  display.drawLine(56,54,72,54,BLACK);
  int tongueX = flip ? 60 : 62;
  int notchX  = tongueX + 1;
  display.drawFastHLine(notchX, 54, 6, WHITE);
  display.fillRoundRect(tongueX, 55, 8, 5, 2, WHITE);
  display.drawRoundRect(tongueX, 55, 8, 5, 2, BLACK);
  display.drawFastVLine(tongueX + 4, 56, 3, BLACK);
  display.display();
}

// ============================================================================
// Menu Rendering
// ============================================================================
static void drawMain() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setTextWrap(false);
  for (int i = 0; i < MAIN_COUNT; i++) {
    display.setCursor(0, i*ROW_H);
    display.print(i == mainIndex ? "> " : "  ");
    display.print(mainItems[i]);
  }
  display.display();
}

static void drawSub() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setTextWrap(false);

  if (inSettingsSub) {
    // SETTINGS submenu: [Sound: On/Off], [Overlay: On/Off], [Menu]
    const int count = 3;
    for (int i = 0; i < count; ++i) {
      display.setCursor(0, i * ROW_H);
      display.print(i == subIndex ? "> " : "  ");
      if (i == 0) {
        display.print("Sound: ");
        display.print(soundOff ? "Off" : "On");
      } else if (i == 1) {
        display.print("Overlay: ");
        // When overlayOff is true, the overlay (panda) is disabled
        display.print(overlayOff ? "Off" : "On");
      } else {
        display.print("Menu");
      }
    }
    display.display();
    return;
  }

  // NEW: Dashboard Yes/No prompt
  if (inDashPrompt) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setTextWrap(false);

    display.setCursor(0, 0);
    display.print("Use your desktop?");

    // subIndex: 0 -> Yes, 1 -> No
    display.setCursor(0, ROW_H * 2);
    display.print(subIndex == 0 ? "> Yes" : "  Yes");
    display.setCursor(0, ROW_H * 3);
    display.print(subIndex == 1 ? "> No"  : "  No");

    display.display();
    return;
  }

  // NEW: RF preset/tuning simple view
  if (inRFSettings) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0,0);
    display.print("RF Presets/Tuning");
    display.setCursor(0,12);
    display.print("Use WebUI /rf/*");
    display.setCursor(0,24);
    display.print("Long press = back");
    display.display();
    return;
  }

  // Original Wi-Fi / BT / RF submenus and Honeypots
  const char** items = nullptr;
  int count = 0;
  if (inWifiSub) {
    items = wifiItems; count = WIFI_SUB_COUNT;
  } else if (inHoneypotsSub) {
    items = hpItems; count = HP_SUB_COUNT;
  } else if (inRFSub) {
    items = rfItems; count = RF_SUB_COUNT;
  } else {
    items = btItems; count = BT_SUB_COUNT;
  }

  int maxTop = (count > LIST_ROWS) ? (count - LIST_ROWS) : 0;
  if (topRow < 0) topRow = 0;
  if (topRow > maxTop) topRow = maxTop;

  int end = topRow + LIST_ROWS; if (end > count) end = count;
  for (int i = topRow, line = 0; i < end; ++i, ++line) {
    display.setCursor(0, line * ROW_H);
    display.print(i == subIndex ? "> " : "  ");
    display.print(items[i]);
  }

  // tiny scrollbar
  if (count > LIST_ROWS) {
    int trackH = LIST_ROWS * ROW_H;
    int barH = (trackH * LIST_ROWS) / count; if (barH < 4) barH = 4;
    int barY = (trackH * subIndex) / count;
    int x = SCREEN_WIDTH - 3;
    display.drawFastVLine(x, 0, trackH, WHITE);
    display.fillRect(x - 1, barY, 2, barH, WHITE);
  }
  display.display();
}

// ============================================================================
// Wi-Fi Packet Callback (promiscuous mode) — runs per selected Wi-Fi detector
// ============================================================================
static void IRAM_ATTR packetHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (mode < MODE_DEAUTH || mode > MODE_BCAST_DATA) return;

  auto* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* d = pkt->payload;
  int pktLen = pkt->rx_ctrl.sig_len;
  unsigned long now = millis();
  uint8_t fctl = d[0];

  // Learn BSSIDs from beacons for spoofed-mgmt heuristic
  if ((fctl & 0xF0) == 0x80 && pktLen >= 38) addKnownBssid(d + 10);

  // Deauth
  if (mode == MODE_DEAUTH && ((fctl & 0xFC) == 0xC0)) { lastDeauthTime = now; deauthDetected = true; }

  // Disassoc flood
  if (mode == MODE_DISASSOC && ((fctl & 0xFC) == 0xA0)) { disassocDetected = true; lastDisassocTime = now; }

  // Probe flood (Probe Request)
  if (mode == MODE_PROBE && ((fctl & 0xF0) == 0x40)) {
    if (probeWindowStart==0 || now - probeWindowStart > PROBE_WINDOW_MS) resetProbeWindow();
    uint8_t* src = d + 10;
    ProbeMacEntry* e = getProbeEntry(src);
    if (e) {
      e->count++; probeTotalCount++;
      int ie = 24;
      if (pktLen > ie+2) {
        uint8_t id = d[ie], ln = d[ie+1];
        if (id==0 && pktLen >= ie+2+ln && ln<=32) {
          uint16_t sig = ssidSig(d+ie+2, ln);
          bool seen=false; for(int i=0;i<e->sigCount;i++) if(e->sigs[i]==sig){seen=true;break;}
          if(!seen && e->sigCount<MAX_SIGS_PER_MAC) e->sigs[e->sigCount++]=sig;
        }
      }
      if (e->count >= PROBE_PER_MAC_THRESH || probeTotalCount >= PROBE_TOTAL_THRESH) {
        probeFloodDetected = true; lastProbeTime = now;
      }
    }
  }

  // RTS/CTS flood
  if (mode == MODE_RTSCTS && (((fctl & 0xFC) == 0xB4) || ((fctl & 0xFC) == 0xC4))) {
    if (rtsctsWindowStart==0 || now - rtsctsWindowStart > RTSCTS_WINDOW_MS) {
      rtsctsWindowStart = now; rtsctsCount = 0; navHighCount = 0;
    }
    rtsctsCount++;
    uint16_t dur = d[2] | (uint16_t(d[3])<<8);
    if (dur >= NAV_DUR_US_THRESH) navHighCount++;
    if (rtsctsCount >= RTSCTS_COUNT_THRESH || navHighCount >= NAV_HIGH_COUNT_THRESH) {
      rtsctsDetected = true; lastRtsCtsTime = now;
    }
  }

  // EAPOL storm (data frames)
  if (mode == MODE_EAPOL && type == WIFI_PKT_DATA && pktLen > 40) {
    int hdr = 24 + ((fctl & 0x08) ? 4 : 0);
    if (pktLen > hdr+8) {
      uint8_t* llc = d + hdr;
      if (llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
          llc[6]==0x88 && llc[7]==0x8E) {
        if (eapolWindowStart==0 || now - eapolWindowStart > EAPOL_WINDOW_MS) {
          eapolWindowStart = now; eapolCount = 0;
        }
        if (++eapolCount >= EAPOL_THRESH) { eapolStormDetected = true; lastEapolTime = now; }
      }
    }
  }

  // CSA attack (beacon IE 37)
  if (mode == MODE_CSA && ((fctl & 0xF0) == 0x80) && pktLen > 36) {
    uint8_t* bssid = d + 10;
    if (csaWindowStart==0 || now - csaWindowStart > CSA_WINDOW_MS) {
      resetBssidWindow(csaEntries, csaEntryCount, csaWindowStart);
    }
    int ies = 36, rem = pktLen - ies, i=0;
    while (i+2 <= rem) {
      uint8_t id = d[ies+i], ln = d[ies+i+1];
      if (i+2+ln > rem) break;
      if (id == 37) {
        CountEntry* ce = getEntry(csaEntries, csaEntryCount, bssid);
        if (ce && (++ce->count >= CSA_PER_BSSID_THRESH)) { csaDetected = true; lastCsaTime = now; }
      }
      i += 2 + ln;
    }
  }

  // Spoofed mgmt (deauth/disassoc not from known BSSID)
  if (mode == MODE_SPOOFEDMGMT && (((fctl & 0xFC)==0xC0) || ((fctl & 0xFC)==0xA0))) {
    uint8_t* tx = d + 10;
    if (!isKnownBssid(tx)) { spoofMgmtDetected = true; lastSpoofTime = now; }
  }

  // Rogue AP (same SSID hops across channels quickly)
  if (mode == MODE_ROGUE && ((fctl & 0xF0) == 0x80) && pktLen >= 38) {
    uint8_t* bssid = d + 10;
    int off = 36, len = d[off+1]; if (len > 32) len = 32;
    char ssid[33]; memcpy(ssid, d+off+2, len); ssid[len] = 0;

    int idx = -1;
    for (int i = 0; i < apCount; i++) if (!strcmp(apList[i].ssid, ssid)) { idx = i; break; }
    if (idx < 0 && apCount < MAX_APS) {
      idx = apCount++;
      strcpy(apList[idx].ssid, ssid);
      memcpy(apList[idx].bssids[0], bssid, 6);
      apList[idx].bssidCount = 1;
      apList[idx].channelsSeen = 1 << currentChannel;
      apList[idx].newChannelCount = 0;
      apList[idx].firstDetectTime = 0;
      apList[idx].seenOpen = false; apList[idx].seenRSN = false;
      saveAPList();
    } else if (idx >= 0) {
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
                bssid[2]==whitelistOUI[k][2]) { allowed = true; break; }
          }
          if (!allowed) { rogueDetected = true; lastRogueTime = now; }
          apList[idx].newChannelCount = 0;
          apList[idx].firstDetectTime = 0;
          saveAPList();
        }
      }
    }
  }

  // Beacon flood (per-SSID rate)
  if (mode == MODE_BEACON && ((fctl & 0xF0) == 0x80) && pktLen >= 38) {
    int off = 36, len = d[off+1]; if (len>32) len=32;
    char ssid[33]; memcpy(ssid, d + off + 2, len); ssid[len] = 0;

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

  // Beacon anomaly (malformed IEs/empty SSID)
  if (mode == MODE_BEACON_ANOM && ((fctl & 0xF0) == 0x80) && pktLen > 36) {
    if (beaconAnomWindowStart==0 || now - beaconAnomWindowStart > BEACON_ANOM_WINDOW_MS) {
      beaconAnomWindowStart = now; zeroSsidCount=0; badIeCount=0;
    }
    int ssidLen = d[36+1];
    if (ssidLen == 0) zeroSsidCount++;
    int ies = 36, rem = pktLen - ies, i=0; bool bad=false;
    while (i+2 <= rem) {
      uint8_t ln = d[ies+i+1];
      if (i+2+ln > rem) { bad=true; break; }
      i += 2 + ln;
    }
    if (bad) badIeCount++;
    if (zeroSsidCount >= ZERO_SSID_THRESH || badIeCount >= BAD_IE_THRESH) {
      beaconAnomDetected = true; lastBeaconAnomTime = now;
    }
  }

  // WPS exposure / spam (Vendor IE 221, OUI 00:50:F2, type 0x04)
  if (mode == MODE_WPS && ((fctl & 0xF0) == 0x80) && pktLen > 36) {
    uint8_t* bssid = d + 10;
    if (wpsWindowStart==0 || now - wpsWindowStart > WPS_WINDOW_MS) {
      resetBssidWindow(wpsEntries, wpsEntryCount, wpsWindowStart);
    }
    int ies = 36, rem = pktLen - ies, i=0;
    while (i+2 <= rem) {
      uint8_t id = d[ies+i], ln = d[ies+i+1];
      if (i+2+ln > rem) break;
      if (id==221 && ln>=4) {
        uint8_t* vd = d+ies+i+2;
        if (vd[0]==0x00 && vd[1]==0x50 && vd[2]==0xF2 && vd[3]==0x04) {
          CountEntry* we = getEntry(wpsEntries, wpsEntryCount, bssid);
          if (we && (++we->count >= WPS_PER_BSSID_THRESH)) { wpsSpamDetected = true; lastWpsTime = now; }
        }
      }
      i += 2 + ln;
    }
  }

  // RSN mismatch (same SSID seen open and protected)
  if (mode == MODE_RSN_MISMATCH && ((fctl & 0xF0) == 0x80) && pktLen > 36) {
    int off = 36, len = d[off+1]; if (len > 32) len = 32;
    char ssid[33]; memcpy(ssid, d+off+2, len); ssid[len] = 0;

    bool hasRSN=false, isOpen=true;
    int ies = 36, rem = pktLen - ies, i=0;
    while (i+2 <= rem) {
      uint8_t id = d[ies+i], ln = d[ies+i+1];
      if (i+2+ln > rem) break;
      if (id == 48) { hasRSN = true; isOpen = false; }
      i += 2 + ln;
    }
    int idx=-1;
    for(int k=0;k<apCount;k++) if(!strcmp(apList[k].ssid,ssid)){ idx=k; break; }
    if (idx < 0 && apCount < MAX_APS) {
      idx = apCount++; strcpy(apList[idx].ssid, ssid);
      apList[idx].bssidCount=0; apList[idx].channelsSeen=0; apList[idx].newChannelCount=0; apList[idx].firstDetectTime=0;
      apList[idx].seenOpen=false; apList[idx].seenRSN=false;
    }
    if (idx>=0){
      if(hasRSN) apList[idx].seenRSN=true;
      if(isOpen) apList[idx].seenOpen=true;
      if(apList[idx].seenOpen && apList[idx].seenRSN){
        rsnMismatchDetected=true; lastRsnMismatchTime=now;
      }
    }
  }

  // ARP spoof (multiple MACs claim same IP via ARP replies)
  if (mode == MODE_ARP && type == WIFI_PKT_DATA && pktLen > 40) {
    int hdr = 24 + ((fctl & 0x08) ? 4 : 0);
    if (pktLen > hdr+16) {
      uint8_t* llc = d + hdr;
      if (llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
          llc[6]==0x08 && llc[7]==0x06) {
        uint8_t* arp = llc + 8;
        if (((arp[6]<<8)|arp[7]) == 2) { // reply
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
          } else if (aidx >= 0) {
            bool seen=false;
            for (int j = 0; j < arpList[aidx].macCount; j++)
              if (macEq(arpList[aidx].macs[j], smac)) { seen=true; break; }
            if (!seen && arpList[aidx].macCount < MAX_MACS_PER_IP) {
              macCpy(arpList[aidx].macs[arpList[aidx].macCount++], smac);
              arpDetected = true; lastARPTime = now;
            }
          }
        }
      }
    }
  }

  // Broadcast data spike (DA = ff:ff:ff:ff:ff:ff)
  if (mode == MODE_BCAST_DATA && type == WIFI_PKT_DATA && pktLen >= 10) {
    const uint8_t* da = d + 4;
    bool isBcast = true; for(int i=0;i<6;i++) if (da[i] != 0xFF) { isBcast=false; break; }
    if (isBcast) {
      if (bcastWindowStart==0 || now - bcastWindowStart > BCAST_WINDOW_MS) { bcastWindowStart = now; bcastCount = 0; }
      if ((++bcastCount) >= BCAST_DATA_THRESH) { bcastDataDetected = true; lastBcastDataTime = now; }
    }
  }
}

// ============================================================================
// BLE Monitor (10 scan-only detectors run individually)
// ============================================================================
namespace BLEMON {
  #ifndef BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP
  #define BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP 0x04
  #endif

  static bool parseAddrStr(const std::string& s, uint8_t out[6]) {
    int b[6];
    if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
      for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
      return true;
    }
    memset(out, 0, 6);
    return false;
  }

  static const uint32_t WINDOW_MS = 3000;

  static const int TH_ADV_PER_MAC          = 220;
  static const int TH_UUID_FLOOD           = 320;
  static const int TH_ADDRHOP_DISTINCT_MAC = 14;
  static const int TH_SERVICE_SPOOF_CHG    = 3;
  static const int TH_MFR_DOMINANCE_PCT    = 80;
  static const int TH_MFR_UNIQUE_CHURN     = 18;
  static const int TH_SCANRSP_PER_MAC      = 90;
  static const int TH_SCANRSP_RATIO_NUM    = 2;
  static const int TH_SCANRSP_RATIO_DEN    = 1;
  static const int TH_INTERVAL_MIN_MS      = 20;
  static const int TH_INTERVAL_SAMPLES     = 30;
  static const int TH_REPLAY_CLONE_MACS    = 10;
  static const int TH_NAME_SIMILAR         = 1;
  static const int TH_RSSI_JUMP_DB         = 36;
  static const int TH_RSSI_JUMP_MS         = 100;

  #define MAX_BLE_MAC       60
  #define MAX_UUID_KEYS     30
  #define MAX_SIG_KEYS      30
  #define MAX_MFR_KEYS      20
  #define MAX_NAME_KEYS     20
  #define MAX_PAYLOAD_KEYS  30
  #define MAX_MACS_PER_KEY  10

  static inline uint16_t h16_mix(uint16_t a, uint16_t b){ uint16_t x=a ^ (uint16_t)(b*40503u); return (uint16_t)((x<<5)|(x>>11)); }
  static uint16_t h16_bytes(const uint8_t* p, size_t n){ uint16_t h=0; for(size_t i=0;i<n;i++) h=h16_mix(h, p[i]); return h; }
  static uint16_t h16_str(const std::string& s){ return h16_bytes((const uint8_t*)s.data(), s.size()); }

  static char normc(char c){
    if (c>='A' && c<='Z') c = c - 'A' + 'a';
    if (c=='0') return 'o'; if (c=='1') return 'l'; if (c=='3') return 'e';
    if (c=='5') return 's'; if (c=='7') return 't';
    return c;
  }
  static uint16_t h16_normname(const std::string& s){ uint16_t h=0; for(char c: s){ h=h16_mix(h, normc(c)); } return h; }

  struct MacEntry {
    uint8_t  mac[6];
    uint32_t advCount, scanRspCount, scanRspBytes;
    uint32_t lastTs, lastDelta, sumDelta;
    uint16_t nIntervals;
    int8_t   lastRSSI;
    bool     hasLast;
  };
  static MacEntry macs[MAX_BLE_MAC]; static int macN=0;

  struct KVCount { uint16_t key; uint16_t count; uint16_t aux; };
  static KVCount uuidTbl[MAX_UUID_KEYS]; static int uuidN=0;

  struct SigKey {
    uint16_t sig;
    uint16_t macHash[MAX_MACS_PER_KEY];
    uint8_t  macSeenN;
    int8_t   lastRSSI;
    uint32_t lastTs;
  };
  static SigKey sigTbl[MAX_SIG_KEYS]; static int sigN=0;

  struct NameSig { uint16_t nameHash, baselineSig; uint8_t changes; };
  static NameSig nameTbl[MAX_NAME_KEYS]; static int nameN=0;

  struct MfrKey { uint16_t id, count; };
  static MfrKey mfrTbl[MAX_MFR_KEYS]; static int mfrN=0;
  static uint32_t totalAdvs=0;

  struct PayloadKey { uint16_t ph; uint16_t macHash[MAX_MACS_PER_KEY]; uint8_t macSeenN; };
  static PayloadKey payloadTbl[MAX_PAYLOAD_KEYS]; static int payloadN=0;

  static volatile bool advFlood=false, uuidFlood=false, addrHop=false, serviceSpoof=false, mfrStorm=false;
  static volatile bool scanRspAbuse=false, intervalAnom=false, replayClone=false, nameSquat=false, rssiTeleport=false;
  static volatile unsigned long advFloodAt=0, uuidFloodAt=0, addrHopAt=0, serviceSpoofAt=0, mfrStormAt=0;
  static volatile unsigned long scanRspAt=0, intervalAt=0, replayAt=0, nameSquatAt=0, rssiTpAt=0;

  static unsigned long windowStart=0;

  static MacEntry* getMac(const uint8_t* mac){
    for(int i=0;i<macN;i++) if(macEq(macs[i].mac,mac)) return &macs[i];
    if(macN<MAX_BLE_MAC){
      memset(&macs[macN], 0, sizeof(MacEntry));
      macCpy(macs[macN].mac,mac);
      return &macs[macN++];
    }
    return nullptr;
  }
  static KVCount* getKV(KVCount* t,int& n,int max,uint16_t key){
    for(int i=0;i<n;i++) if(t[i].key==key) return &t[i];
    if(n<max){ t[n].key=key; t[n].count=0; t[n].aux=0; return &t[n++]; }
    return nullptr;
  }
  static SigKey* getSig(uint16_t s){
    for(int i=0;i<sigN;i++) if(sigTbl[i].sig==s) return &sigTbl[i];
    if(sigN<MAX_SIG_KEYS){ sigTbl[sigN].sig=s; sigTbl[sigN].macSeenN=0; sigTbl[sigN].lastRSSI=0; sigTbl[sigN].lastTs=0; return &sigTbl[sigN++]; }
    return nullptr;
  }
  static NameSig* getName(uint16_t nh){
    for(int i=0;i<nameN;i++) if(nameTbl[i].nameHash==nh) return &nameTbl[i];
    if(nameN<MAX_NAME_KEYS){ nameTbl[nameN].nameHash=nh; nameTbl[nameN].baselineSig=0; nameTbl[nameN].changes=0; return &nameTbl[nameN++]; }
    return nullptr;
  }
  static PayloadKey* getPayload(uint16_t ph){
    for(int i=0;i<payloadN;i++) if(payloadTbl[i].ph==ph) return &payloadTbl[i];
    if(payloadN<MAX_PAYLOAD_KEYS){ payloadTbl[payloadN].ph=ph; payloadTbl[payloadN].macSeenN=0; return &payloadTbl[payloadN++]; }
    return nullptr;
  }

  static bool looksLikeProtected(const std::string& nm){
    if(nm.empty()) return false;
    const char* protectedNames[] = { "AirTag","AirPods","Tile","Keyboard","Mouse","Beats" };
    char buf[24]; size_t L = nm.size(); if(L>23) L=23;
    for(size_t i=0;i<L;i++) buf[i]=normc(nm[i]); buf[L]=0;
    for (unsigned i=0;i<sizeof(protectedNames)/sizeof(protectedNames[0]); i++){
      const char* p = protectedNames[i];
      size_t lp=strlen(p); if (lp>23) lp=23;
      char pn[24]; for(size_t k=0;k<lp;k++){ char c=p[k]; if(c>='A'&&c<='Z') c=c-'A'+'a'; pn[k]=c; } pn[lp]=0;
      int mism=0; size_t m = (L<lp?L:lp);
      for(size_t k=0;k<m;k++) if(buf[k]!=pn[k]) mism++;
      mism += (int)abs((int)L - (int)lp);
      if (mism <= 1) return true;
    }
    return false;
  }

  static void buildHashes(const NimBLEAdvertisedDevice* d, uint16_t& nameH, uint16_t& servH, uint16_t& mfrH, uint16_t& sigH, uint16_t& payloadH, uint16_t& companyId){
    nameH=servH=mfrH=0; companyId=0;
    if (d->haveName()) nameH = h16_normname(d->getName());
    if (d->haveManufacturerData()){
      const std::string& md = d->getManufacturerData();
      if (md.size()>=2) companyId = ((uint8_t)md[1]<<8) | (uint8_t)md[0];
      mfrH = h16_str(md);
    }
    uint8_t cnt = d->getServiceUUIDCount();
    for(uint8_t i=0;i<cnt;i++){
      NimBLEUUID u = d->getServiceUUID(i);
      servH = h16_mix(servH, h16_str(u.toString()));
    }
    sigH     = h16_mix(h16_mix(nameH, servH), mfrH);
    payloadH = h16_mix(servH, mfrH);
  }

  class ScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* d) override {
      unsigned long now = millis();

      uint8_t mac[6];
      parseAddrStr(d->getAddress().toString(), mac);

      MacEntry* me = getMac(mac); if (!me) return;

      uint16_t nameH, servH, mfrH, sigH, payloadH, companyId;
      buildHashes(d, nameH, servH, mfrH, sigH, payloadH, companyId);
      int rssi = d->getRSSI();

      uint8_t advType = d->getAdvType();
      bool isScanRsp = (advType == BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP);

      me->advCount++;
      if (isScanRsp) {
        me->scanRspCount++;
        if (d->haveManufacturerData())
          me->scanRspBytes += d->getManufacturerData().size();
      }
      if (me->hasLast) {
        uint32_t dt = now - me->lastTs; me->lastDelta = dt;
        if (dt > 0 && dt < 2000) { me->sumDelta += dt; me->nIntervals++; }
      }
      me->lastTs = now; me->hasLast = true; me->lastRSSI = (int8_t)rssi;
      totalAdvs++;

      switch (mode) {
        case MODE_BT_ADV_FLOOD:
          if (me->advCount >= 220){ advFlood = true; advFloodAt = now; }
          break;
        case MODE_BT_UUID_FLOOD: {
          uint16_t key = servH ? servH : mfrH;
          KVCount* kv = getKV(uuidTbl, uuidN, MAX_UUID_KEYS, key);
          if (kv && (++kv->count >= 320)){ uuidFlood = true; uuidFloodAt = now; }
        } break;
        case MODE_BT_ADDR_HOP: {
          SigKey* s = getSig(sigH);
          if (s){
            uint16_t mh = h16_bytes(mac,6);
            bool seen=false; for(uint8_t i=0;i<s->macSeenN;i++) if (s->macHash[i]==mh){ seen=true; break; }
            if (!seen && s->macSeenN<MAX_MACS_PER_KEY) s->macHash[s->macSeenN++]=mh;
            if (s->macSeenN >= 14){ addrHop=true; addrHopAt=now; }
          }
        } break;
        case MODE_BT_SERVICE_SPOOF: {
          NameSig* ns = getName(nameH);
          if (ns){
            if (ns->baselineSig==0) ns->baselineSig = sigH;
            else if (ns->baselineSig != sigH){
              ns->changes++; ns->baselineSig = sigH;
              if (ns->changes >= 3){ serviceSpoof=true; serviceSpoofAt=now; }
            }
          }
        } break;
        case MODE_BT_MFR_STORM: {
          if (companyId){
            MfrKey* mk=nullptr;
            for(int i=0;i<mfrN;i++) if(mfrTbl[i].id==companyId){ mk=&mfrTbl[i]; break; }
            if (!mk && mfrN<MAX_MFR_KEYS){ mfrTbl[mfrN].id=companyId; mfrTbl[mfrN].count=0; mk=&mfrTbl[mfrN++]; }
            if (mk) mk->count++;
            for(int i=0;i<mfrN;i++){
              if (totalAdvs>50 && (int)((mfrTbl[i].count*100) / (totalAdvs?totalAdvs:1)) >= 80){
                mfrStorm=true; mfrStormAt=now; break;
              }
            }
            if (mfrN >= 18){ mfrStorm=true; mfrStormAt=now; }
          }
        } break;
        case MODE_BT_SCANRSP_ABUSE:
          if (me->scanRspCount >= 90) { scanRspAbuse=true; scanRspAt=now; }
          if (me->advCount >= 10 && (me->scanRspCount * 1) >= (me->advCount * 2)) { scanRspAbuse=true; scanRspAt=now; }
          break;
        case MODE_BT_INTERVAL_ANOM:
          if (me->nIntervals >= 30){
            uint32_t avg = me->sumDelta / (me->nIntervals ? me->nIntervals : 1);
            if ((int)avg < 20){ intervalAnom=true; intervalAt=now; }
          }
          break;
        case MODE_BT_REPLAY_CLONE: {
          PayloadKey* pk = getPayload(payloadH);
          if (pk){
            uint16_t mh = h16_bytes(mac,6);
            bool seen=false; for(uint8_t i=0;i<pk->macSeenN;i++) if(pk->macHash[i]==mh){ seen=true; break; }
            if (!seen && pk->macSeenN<MAX_MACS_PER_KEY) pk->macHash[pk->macSeenN++]=mh;
            if (pk->macSeenN >= 10){ replayClone=true; replayAt=now; }
          }
        } break;
        case MODE_BT_NAME_SQUAT:
          if (d->haveName() && looksLikeProtected(d->getName())) { nameSquat=true; nameSquatAt=now; }
          break;
        case MODE_BT_RSSI_TELEPORT: {
          SigKey* s = getSig(sigH);
          if (s){
            if (s->lastTs>0){
              uint32_t dt = now - s->lastTs;
              int dr = abs((int)rssi - (int)s->lastRSSI);
              if ((int)dt <= 100 && dr >= 36){ rssiTeleport=true; rssiTpAt=now; }
            }
            s->lastTs = now; s->lastRSSI = (int8_t)rssi;
          }
        } break;
        default: break;
      }
    }
  } scanCB;

  static NimBLEScan* scan=nullptr;

  static void start(){
    static bool inited=false;
    if (!inited){ NimBLEDevice::init(""); inited=true; }
    scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&scanCB, true);
    scan->setActiveScan(true);
    scan->setInterval(45); scan->setWindow(30);

    macN=uuidN=sigN=mfrN=nameN=payloadN=0; totalAdvs=0;
    advFlood=uuidFlood=addrHop=serviceSpoof=mfrStorm=false;
    scanRspAbuse=intervalAnom=replayClone=nameSquat=rssiTeleport=false;
    advFloodAt=uuidFloodAt=addrHopAt=serviceSpoofAt=mfrStormAt=0;
    scanRspAt=intervalAt=replayAt=nameSquatAt=rssiTpAt=0;
    windowStart=millis();

    scan->start(0, false);
  }

  static void stop(){ if (scan && scan->isScanning()) scan->stop(); }

  static void tick(){
    unsigned long now = millis();
    if (now - windowStart >= WINDOW_MS){
      for(int i=0;i<macN;i++){ macs[i].advCount=0; macs[i].scanRspCount=0; macs[i].scanRspBytes=0; macs[i].sumDelta=0; macs[i].nIntervals=0; }
      uuidN=0;
      for(int i=0;i<sigN;i++){ sigTbl[i].macSeenN=0; }
      mfrN=0; totalAdvs=0; payloadN=0;
      windowStart = now;
    }

    auto off = [&](volatile bool& f, volatile unsigned long& t, unsigned long dur){ if (f && now - t > dur) f=false; };
    off(advFlood,advFloodAt,ALERT_DURATION);
    off(uuidFlood,uuidFloodAt,ALERT_DURATION);
    off(addrHop,addrHopAt,ALERT_DURATION);
    off(serviceSpoof,serviceSpoofAt,ALERT_DURATION);
    off(mfrStorm,mfrStormAt,ALERT_DURATION);
    off(scanRspAbuse,scanRspAt,ALERT_DURATION);
    off(intervalAnom,intervalAt,ALERT_DURATION);
    off(replayClone,replayAt,ALERT_DURATION);
    off(nameSquat,nameSquatAt,ALERT_DURATION);
    off(rssiTeleport,rssiTpAt,ALERT_DURATION);
  }

  static bool anyAlert() {
    return advFlood || uuidFlood || addrHop || serviceSpoof || mfrStorm ||
           scanRspAbuse || intervalAnom || replayClone || nameSquat || rssiTeleport;
  }

  // === Added: snapshot for per-type WS pushes ===
  enum AlertBit {
    AB_ADV_FLOOD      = 1<<0, AB_UUID_FLOOD   = 1<<1, AB_ADDR_HOP     = 1<<2,
    AB_SERVICE_SPOOF  = 1<<3, AB_MFR_STORM    = 1<<4, AB_SCANRSP_ABUSE= 1<<5,
    AB_INTERVAL_ANOM  = 1<<6, AB_REPLAY_CLONE = 1<<7, AB_NAME_SQUAT   = 1<<8,
    AB_RSSI_TELEPORT  = 1<<9
  };
  static uint32_t snapshotAlerts(){
    uint32_t m=0;
    if (advFlood)       m|=AB_ADV_FLOOD;
    if (uuidFlood)      m|=AB_UUID_FLOOD;
    if (addrHop)        m|=AB_ADDR_HOP;
    if (serviceSpoof)   m|=AB_SERVICE_SPOOF;
    if (mfrStorm)       m|=AB_MFR_STORM;
    if (scanRspAbuse)   m|=AB_SCANRSP_ABUSE;
    if (intervalAnom)   m|=AB_INTERVAL_ANOM;
    if (replayClone)    m|=AB_REPLAY_CLONE;
    if (nameSquat)      m|=AB_NAME_SQUAT;
    if (rssiTeleport)   m|=AB_RSSI_TELEPORT;
    return m;
  }
} // namespace BLEMON

// ============================================================================
// RF / Sub-GHz (CC1101) Engine — BandScan, Monitor, Waterfall, OOK, 2-FSK, IDS
// Requires: ELECHOUSE_CC1101_SRC_DRV.h
// Pins used: RF_CS_PIN, RF_SCK_PIN, RF_MISO_PIN, RF_MOSI_PIN, RF_GDO0_PIN
// ============================================================================
namespace RF {

  struct Preset {
    const char* name;
    float  fMHz;
    uint32_t dr_bps;
    uint32_t rx_bw_hz;
    uint8_t  mod;     // 0=2-FSK, 1=GFSK, 2=ASK/OOK, 3=4-FSK, 4=MSK (lib maps subset)
    uint8_t  sync;    // 0=disabled, 1=30/32, 2=16/16 (approx)
    int      thresh;  // RSSI / edge threshold
  };

  // A few practical region profiles
  static Preset PRESETS[] = {
    {"US_315_OOK", 315.00f,   2400,  100000, 2, 1, -65},
    {"US_433_OOK", 433.92f,   2400,  100000, 2, 1, -65},
    {"EU_433_2FSK",433.92f,  38400,  203000, 0, 2, -70},
    {"EU_868_2FSK",868.30f,  50000,  203000, 0, 2, -70},
    {"US_915_2FSK",915.00f, 100000,  270000, 0, 2, -70},
    {"US_915_OOK", 915.00f,   4800,  135000, 2, 1, -65}
  };
  static const int PRESET_N = sizeof(PRESETS)/sizeof(PRESETS[0]);

  // State
  static bool   inited=false, running=false;
  static Mode   curMode=MODE_NONE;
  static float  fMHz = 433.92f;
  static uint32_t dr_bps=2400, rx_bw_hz=100000;
  static uint8_t mod=2, sync=1;
  static int     thresh=-65;

  // Band scan parameters
  static float  scanStart=300.0f, scanStop=930.0f, scanStep=0.4f; // MHz
  static unsigned long lastScanStep=0;
  static const unsigned SCAN_DWELL_MS = 22;

  // Waterfall buffer (coarse)
  #define WF_W  64
  #define WF_H  32
  static int8_t wf[WF_H][WF_W]; // dBm values
  static int    wfX=0;

  // OOK edge capture
  #define OOK_MAX_EDGES  4096
  static uint32_t edgeTs[OOK_MAX_EDGES]; // micros
  static uint16_t edgeN=0;
  static bool     capturing=false;
  static unsigned long capStartMs=0;
  static const unsigned CAPTURE_MS = 2500;

  // 2-FSK capture — naive sync gating using RSSI threshold
  #define FSK_MAX_SAMPLES 4096
  static int8_t  fskRssi[FSK_MAX_SAMPLES];
  static uint16_t fskN=0;

  // IDS (jam/flood) heuristics
  static unsigned long idsWindowStart=0;
  static const unsigned IDS_WIN_MS=1200;
  static int   idsAbove=0, idsSamples=0;
  static bool  idsAlert=false; static unsigned long idsAt=0;

  // File helpers
  static String nowName(const char* tag){
    time_t t = time(nullptr);
    struct tm* tm = localtime(&t);
    char buf[32];
    if (tm) snprintf(buf,sizeof(buf),"/rf/%04d%02d%02d_%02d%02d%02d_%s.bin",
                     1900+tm->tm_year,1+tm->tm_mon,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,tag);
    else snprintf(buf,sizeof(buf),"/rf/%lu_%s.bin",(unsigned long)millis(),tag);
    return String(buf);
  }
  static void ensureDir(){ if (!SPIFFS.exists("/rf")) SPIFFS.mkdir("/rf"); }

  // CC1101 init + tuning
  static void hwInit(){
    if (inited) return;
    pinMode(RF_GDO0_PIN, INPUT);
    ELECHOUSE_cc1101.setSpiPin(RF_SCK_PIN, RF_MISO_PIN, RF_MOSI_PIN, RF_CS_PIN);
    ELECHOUSE_cc1101.Init();
    inited = true;
  }
  static void apply(){
    hwInit();
    ELECHOUSE_cc1101.setMHZ(fMHz);
    ELECHOUSE_cc1101.setRxBW(rx_bw_hz);
    ELECHOUSE_cc1101.setDRate(dr_bps);
    ELECHOUSE_cc1101.setModulation(mod); // lib: 0=2-FSK, 1=GFSK, 2=ASK/OOK, 3=4-FSK, 4=MSK
    ELECHOUSE_cc1101.setSyncMode(sync);  // 0..7; we map 0/1/2 to common modes
    ELECHOUSE_cc1101.setPA(0);
    ELECHOUSE_cc1101.SetRx();
  }

  // Public control
  static void start(Mode m){
    curMode = m; running=true; idsAlert=false; idsAbove=0; idsSamples=0; idsWindowStart=millis();

    if (!SPIFFS.begin(true)) Serial.println("[RF] SPIFFS not ready");
    ensureDir();
    apply();

    if (m==MODE_RF_WATERFALL){ memset(wf, -127, sizeof(wf)); wfX=0; }
    if (m==MODE_RF_OOK_CAPTURE){ edgeN=0; capturing=true; capStartMs=millis(); }
    if (m==MODE_RF_2FSK_CAPTURE){ fskN=0; }
  }

  static void stop(){
    running=false; curMode=MODE_NONE;
    // In some versions of ELECHOUSE CC1101 library, setIdle() is named setSidle().
    // Use setSidle() instead to put the transceiver into idle state.
    ELECHOUSE_cc1101.setSidle();
  }

  // Simple RSSI read helper
  static int readRSSI(){
    return ELECHOUSE_cc1101.getRssi();
  }

  // IDS tick
  static void idsTick(){
    int r = readRSSI();
    idsSamples++;
    if (r >= thresh) idsAbove++;
    unsigned long now = millis();
    if (now - idsWindowStart >= IDS_WIN_MS){
      // ratio based
      if (idsSamples >= 50 && (idsAbove*100/idsSamples) >= 80){
        idsAlert = true; idsAt = now;
        pushAlert("RF_IDS", "MEDIUM", "\"note\":\"RSSI jam/flood\",\"ratio\":" + String((idsAbove*100)/idsSamples));
      }
      idsAbove=0; idsSamples=0; idsWindowStart = now;
    }
    if (idsAlert && now - idsAt > 3000) idsAlert=false;
  }

  // Band scan tick
  static void bandScanTick(){
    unsigned long now = millis();
    if (now - lastScanStep < SCAN_DWELL_MS) return;
    lastScanStep = now;

    static float f = scanStart - scanStep;
    f += scanStep; if (f > scanStop) f = scanStart;
    ELECHOUSE_cc1101.setMHZ(f);
    ELECHOUSE_cc1101.SetRx();

    int r = readRSSI();
    // Stream occasional scan points to WS
    static int down=0; if (++down % 5 == 0){
      pushAlert("RF_BANDSCAN","LOW","\"MHz\":"+String(f,2)+",\"rssi\":"+String(r));
    }
  }

  // Monitor & Waterfall
  static void monitorTick(bool doWaterfall){
    int r = readRSSI();
    if (doWaterfall){
      // write column wfX
      for (int y=0;y<WF_H;y++){
        int level = map(r, -100, -20, 0, 100);
        int row = constrain(map(level,0,100,WF_H-1,0),0,WF_H-1);
        wf[row][wfX] = r;
      }
      wfX = (wfX+1)%WF_W;
      // lightweight push
      static unsigned long last=0; unsigned long now=millis();
      if (now-last>400){
        last=now;
        pushAlert("RF_WATERFALL","LOW","\"rssi\":"+String(r)+",\"fMHz\":"+String(fMHz,2));
      }
    } else {
      static unsigned long last=0; unsigned long now=millis();
      if (now-last>350){
        last=now; pushAlert("RF_MONITOR","LOW","\"rssi\":"+String(r)+",\"fMHz\":"+String(fMHz,2));
      }
    }
  }

  // OOK capture using GDO0 edges
  static void ookTick(){
    if (!capturing) return;
    static int last = digitalRead(RF_GDO0_PIN);
    int cur = digitalRead(RF_GDO0_PIN);
    if (cur != last){
      if (edgeN < OOK_MAX_EDGES) edgeTs[edgeN++] = micros();
      last = cur;
    }
    if (millis() - capStartMs >= CAPTURE_MS){
      capturing=false;
      // write deltas
      ensureDir();
      String fn = nowName("OOK");
      File f = SPIFFS.open(fn, FILE_WRITE);
      if (f){
        // header: 'O','O','K', version=1, count
        uint8_t hdr[6]={'O','O','K',1,(uint8_t)(edgeN&0xFF),(uint8_t)(edgeN>>8)};
        f.write(hdr,6);
        for (uint16_t i=1;i<edgeN;i++){
          uint32_t dt = edgeTs[i]-edgeTs[i-1];
          f.write((uint8_t*)&dt, sizeof(dt));
        }
        f.close();
        pushAlert("RF_OOK_CAPTURE","LOW","\"file\":\""+fn+"\",\"edges\":"+String(edgeN));
      } else {
        pushAlert("RF_OOK_CAPTURE","LOW","\"error\":\"file open\"");
      }
    }
  }

  // 2-FSK capture (RSSI stream as proxy; simple sync by threshold crossing)
  static void fskTick(){
    int r = readRSSI();
    if (r >= thresh && fskN < FSK_MAX_SAMPLES){
      fskRssi[fskN++] = (int8_t)r;
    }
    if (fskN >= FSK_MAX_SAMPLES-1){
      ensureDir();
      String fn = nowName("2FSK");
      File f = SPIFFS.open(fn, FILE_WRITE);
      if (f){
        uint8_t hdr[6]={'F','S','K',1,(uint8_t)(fskN&0xFF),(uint8_t)(fskN>>8)};
        f.write(hdr,6);
        f.write((uint8_t*)fskRssi, fskN);
        f.close();
        pushAlert("RF_2FSK_CAPTURE","LOW","\"file\":\""+fn+"\",\"samples\":"+String(fskN));
      }
      fskN=0;
    }
  }

  // Public tick
  static void tick(){
    if (!running) return;
    switch (curMode){
      case MODE_RF_BANDSCAN:    bandScanTick(); idsTick(); break;
      case MODE_RF_MONITOR:     monitorTick(false); idsTick(); break;
      case MODE_RF_WATERFALL:   monitorTick(true); idsTick(); break;
      case MODE_RF_OOK_CAPTURE: ookTick(); idsTick(); break;
      case MODE_RF_2FSK_CAPTURE:fskTick(); idsTick(); break;
      case MODE_RF_IDS:         idsTick(); break;
      default: break;
    }
  }

  // Web helpers
  static String jsonStatus(){
    String s="{";
    s += "\"fMHz\":"+String(fMHz,3)+",";
    s += "\"dr_bps\":"+String((unsigned)dr_bps)+",";
    s += "\"rx_bw_hz\":"+String((unsigned)rx_bw_hz)+",";
    s += "\"mod\":" + String(mod)+",";
    s += "\"sync\":"+ String(sync)+",";
    s += "\"thresh\":"+String(thresh)+",";
    // Append running flag without using operator+ on const char arrays
    s += "\"running\":";
    s += (running ? "true" : "false");
    s += ",";
    s += "\"mode\":\""+ modeName() + "\"";
    s += "}";
    return s;
  }

  static void applyTuning(AsyncWebServerRequest* req){
    if (req->hasParam("mhz", true))     fMHz     = req->getParam("mhz", true)->value().toFloat();
    if (req->hasParam("bw_khz", true))  rx_bw_hz = (uint32_t)(req->getParam("bw_khz", true)->value().toFloat()*1000.0f);
    if (req->hasParam("dr_bps", true))  dr_bps   = req->getParam("dr_bps", true)->value().toInt();
    if (req->hasParam("mod", true))     mod      = (uint8_t)req->getParam("mod", true)->value().toInt();
    if (req->hasParam("sync", true))    sync     = (uint8_t)req->getParam("sync", true)->value().toInt();
    if (req->hasParam("thresh", true))  thresh   = req->getParam("thresh", true)->value().toInt();
    apply();
  }

  static void applyPreset(AsyncWebServerRequest* req){
    if (!req->hasParam("name", true)) return;
    String n = req->getParam("name", true)->value();
    for (int i=0;i<PRESET_N;i++){
      if (n.equalsIgnoreCase(PRESETS[i].name)){
        fMHz = PRESETS[i].fMHz; dr_bps=PRESETS[i].dr_bps; rx_bw_hz=PRESETS[i].rx_bw_hz;
        mod = PRESETS[i].mod; sync=PRESETS[i].sync; thresh=PRESETS[i].thresh;
        apply(); return;
      }
    }
  }

  static void sendFileList(AsyncWebServerRequest* req){
    String j="["; bool first=true;
    File dir = SPIFFS.open("/rf");
    if (dir && dir.isDirectory()){
      File f;
      while ((f = dir.openNextFile())){
        if (!first) j += ",";
        first=false;
        j += "{\"name\":\""+String(f.name())+"\",\"size\":"+String((unsigned)f.size())+"}";
        f.close();
      }
    }
    j += "]";
    req->send(200,"application/json",j);
  }

  // helper to expose IDS alert status for outer logic
  static bool isIdsAlert(){ return idsAlert; }
} // namespace RF

// ============================================================================
// Web helpers & API/WS
// ============================================================================
static bool tokenOK(AsyncWebServerRequest* req) {
  if (!TOKEN || strlen(TOKEN)==0) return true;
  if (req->hasParam("token")) return req->getParam("token")->value() == TOKEN;
  if (req->hasHeader("Authorization")) {
    String h=req->getHeader("Authorization")->value();
    if (h.startsWith("Bearer ")) return h.substring(7)==TOKEN;
  }
  return false;
}

static String modeName(){
  switch(mode){
    case MODE_DEAUTH:        return "DEAUTH";
    case MODE_ROGUE:         return "ROGUE_AP";
    case MODE_ARP:           return "ARP";
    case MODE_BEACON:        return "BEACON";
    case MODE_DISASSOC:      return "DISASSOC";
    case MODE_PROBE:         return "PROBE";
    case MODE_RTSCTS:        return "RTSCTS";
    case MODE_EAPOL:         return "EAPOL";
    case MODE_CSA:           return "CSA";
    case MODE_SPOOFEDMGMT:   return "SPOOFEDMGMT";
    case MODE_BEACON_ANOM:   return "BEACON_ANOM";
    case MODE_WPS:           return "WPS";
    case MODE_RSN_MISMATCH:  return "RSN_MISMATCH";
    case MODE_BCAST_DATA:    return "BCAST_DATA";
    case MODE_BT_ADV_FLOOD:  return "BT_ADV_FLOOD";
    case MODE_BT_UUID_FLOOD: return "BT_UUID_FLOOD";
    case MODE_BT_ADDR_HOP:   return "BT_ADDR_HOP";
    case MODE_BT_SERVICE_SPOOF: return "BT_SERVICE_SPOOF";
    case MODE_BT_MFR_STORM:  return "BT_MFR_STORM";
    case MODE_BT_SCANRSP_ABUSE: return "BT_SCANRSP_ABUSE";
    case MODE_BT_INTERVAL_ANOM: return "BT_INTERVAL_ANOM";
    case MODE_BT_REPLAY_CLONE: return "BT_REPLAY_CLONE";
    case MODE_BT_NAME_SQUAT: return "BT_NAME_SQUAT";
    case MODE_BT_RSSI_TELEPORT: return "BT_RSSI_TELEPORT";
    case MODE_BT_JAM:        return "BT_JAM";
    case MODE_RF_BANDSCAN:     return "RF_BANDSCAN";
    case MODE_RF_MONITOR:      return "RF_MONITOR";
    case MODE_RF_WATERFALL:    return "RF_WATERFALL";
    case MODE_RF_OOK_CAPTURE:  return "RF_OOK_CAPTURE";
    case MODE_RF_2FSK_CAPTURE: return "RF_2FSK_CAPTURE";
    case MODE_RF_IDS:          return "RF_IDS";
    case MODE_HP_FAKE_AP:      return "HP_FAKE_AP";
    case MODE_HP_TELNET:       return "HP_TELNET";
    case MODE_HP_CREDENTIAL:   return "HP_CREDENTIAL";
    case MODE_HP_BLE_BEACON:   return "HP_BLE_BEACON";
    default: return "NONE";
  }
}

static void stopAllDetectors(){
  if (mode >= MODE_DEAUTH && mode <= MODE_BCAST_DATA) esp_wifi_set_promiscuous(false);
  if (mode >= MODE_BT_ADV_FLOOD && mode <= MODE_BT_RSSI_TELEPORT) BLEMON::stop();
  if (mode == MODE_BT_JAM) BLEJAM::stop();
  if (mode >= MODE_RF_BANDSCAN && mode <= MODE_RF_IDS) RF::stop();
  // Stop honeypot servers if running
  if (mode == MODE_HP_FAKE_AP || mode == MODE_HP_CREDENTIAL) {
    dnsServer.stop();
    fakeApServer.end();
    credentialServer.end();
  }
  if (mode == MODE_HP_TELNET) {
    telnetServer.end();
    sshServer.end();
    // Close any open client sessions
    for (int i = 0; i < MAX_SESSIONS; ++i) {
      if (sessions[i].client) sessions[i].client.stop();
      sessions[i] = SessionState();
    }
  }
  // Stop BLE beacon honeypot if active
  if (mode == MODE_HP_BLE_BEACON) {
    stopBleBeaconHoneypot();
  }
  mode = MODE_NONE;
  menuLevel = MAIN;
}

static void startDetectorByName(const String& det){
  stopAllDetectors();
  // Wi-Fi
  if      (det=="DEAUTH")           { mode=MODE_DEAUTH; }
  else if (det=="ROGUE_AP")         { mode=MODE_ROGUE; }
  else if (det=="ARP")              { mode=MODE_ARP; }
  else if (det=="BEACON")           { mode=MODE_BEACON; }
  else if (det=="DISASSOC")         { mode=MODE_DISASSOC; }
  else if (det=="PROBE")            { mode=MODE_PROBE; }
  else if (det=="RTSCTS")           { mode=MODE_RTSCTS; }
  else if (det=="EAPOL")            { mode=MODE_EAPOL; }
  else if (det=="CSA")              { mode=MODE_CSA; }
  else if (det=="SPOOFEDMGMT")      { mode=MODE_SPOOFEDMGMT; }
  else if (det=="BEACON_ANOM")      { mode=MODE_BEACON_ANOM; }
  else if (det=="WPS")              { mode=MODE_WPS; }
  else if (det=="RSN_MISMATCH")     { mode=MODE_RSN_MISMATCH; }
  else if (det=="BCAST_DATA")       { mode=MODE_BCAST_DATA; }
  // BLE scan-only
  else if (det=="BT_ADV_FLOOD")     { mode=MODE_BT_ADV_FLOOD; }
  else if (det=="BT_UUID_FLOOD")    { mode=MODE_BT_UUID_FLOOD; }
  else if (det=="BT_ADDR_HOP")      { mode=MODE_BT_ADDR_HOP; }
  else if (det=="BT_SERVICE_SPOOF") { mode=MODE_BT_SERVICE_SPOOF; }
  else if (det=="BT_MFR_STORM")     { mode=MODE_BT_MFR_STORM; }
  else if (det=="BT_SCANRSP_ABUSE") { mode=MODE_BT_SCANRSP_ABUSE; }
  else if (det=="BT_INTERVAL_ANOM") { mode=MODE_BT_INTERVAL_ANOM; }
  else if (det=="BT_REPLAY_CLONE")  { mode=MODE_BT_REPLAY_CLONE; }
  else if (det=="BT_NAME_SQUAT")    { mode=MODE_BT_NAME_SQUAT; }
  else if (det=="BT_RSSI_TELEPORT") { mode=MODE_BT_RSSI_TELEPORT; }
  // BLE jam
  else if (det=="BT_JAM")           { mode=MODE_BT_JAM; }
  // RF
  else if (det=="RF_BANDSCAN")        { mode=MODE_RF_BANDSCAN; }
  else if (det=="RF_MONITOR")         { mode=MODE_RF_MONITOR; }
  else if (det=="RF_WATERFALL")       { mode=MODE_RF_WATERFALL; }
  else if (det=="RF_OOK_CAPTURE")     { mode=MODE_RF_OOK_CAPTURE; }
  else if (det=="RF_2FSK_CAPTURE")    { mode=MODE_RF_2FSK_CAPTURE; }
  else if (det=="RF_IDS")             { mode=MODE_RF_IDS; }
  // Honeypots via API: start corresponding deception module
  else if (det=="HP_FAKE_AP")        { setupFakeAPHoneypot("Panda_HP_AP","",false); mode=MODE_HP_FAKE_AP; }
  else if (det=="HP_TELNET")         { initTelnetHoneypot(); mode=MODE_HP_TELNET; }
  else if (det=="HP_CREDENTIAL")     { setupCredentialHoneypot("FreeWifi-HP"); mode=MODE_HP_CREDENTIAL; }
  else if (det=="HP_BLE_BEACON")     { initBleBeaconHoneypot("PandaFense-BLE"); mode=MODE_HP_BLE_BEACON; }

  if (mode >= MODE_DEAUTH && mode <= MODE_BCAST_DATA) {
    esp_wifi_set_promiscuous(true);
  } else if (mode >= MODE_BT_ADV_FLOOD && mode <= MODE_BT_RSSI_TELEPORT) {
    BLEMON::start();
  } else if (mode == MODE_BT_JAM) {
    BLEJAM::start();
  } else if (mode >= MODE_RF_BANDSCAN && mode <= MODE_RF_IDS) {
    RF::start(mode);
  }
  menuLevel = ACTIVE;
}

static String jsonStatus() {
  String s="{";
  s += "\"deviceId\":\""+deviceId+"\",";
  s += "\"wifiReady\":" + String(wifiReady?"true":"false") + ",";
  s += "\"apMode\":"   + String(apMode?"true":"false") + ",";
  s += "\"mode\":"     + String((int)mode) + ",";
  s += "\"modeName\":\""+ modeName() + "\",";
  s += "\"menuLevel\":" + String((int)menuLevel) + ",";
  s += "\"soundOff\":" + String(soundOff?"true":"false") + ",";
  s += "\"overlayOff\":" + String(overlayOff?"true":"false");
  s += "}";
  return s;
}

static void wsBroadcast(const String& msg){ ws.textAll(msg); }
static void pushStatus(){ wsBroadcast("{\"event\":\"status\",\"payload\":"+jsonStatus()+"}"); }

static void pushAlert(const String& det, const String& sev, const String& kvpairs) {
  unsigned long ts = millis();
  // Record this alert for overlay-off textual display
  lastAlertName = det;
  lastAlertSev  = sev;
  lastAlertDetail = kvpairs;
  lastAlertTs = ts;
  String p = "{";
  p += "\"deviceId\":\""+deviceId+"\",";
  p += "\"detector\":\""+det+"\",";
  p += "\"severity\":\""+sev+"\",";
  p += "\"ts\":"+String(ts)+",";
  p += "\"details\":{"+kvpairs+"}";
  p += "}";
  wsBroadcast("{\"event\":\"alert\",\"payload\":"+p+"}");
}

// HTTP handlers
static void handleStatus(AsyncWebServerRequest* req){
  if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
  req->send(200,"application/json", jsonStatus());
}

static void handleCmd(AsyncWebServerRequest* req, uint8_t* data, size_t len){
  if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
  String action,detector,state;
  if (req->hasParam("action", true))   action  = req->getParam("action", true)->value();
  if (req->hasParam("detector", true)) detector= req->getParam("detector", true)->value();
  if (req->hasParam("state", true))    state   = req->getParam("state", true)->value();
  if (action=="set" && detector.length()){
    if (state=="start" || state=="true" || state=="1") {
      startDetectorByName(detector);
    } else {
      stopAllDetectors();
    }
    pushStatus();
    req->send(200,"application/json","{\"ok\":true}");
    return;
  }
  req->send(400,"application/json","{\"error\":\"bad_request\"}");
}

static void setupFS(){
  if (!SPIFFS.begin(true)) Serial.println("[FS] mount failed");
}

// ======================================================================
// Honeypot setup and loop functions
// ======================================================================

// Configure and start a fake access point honeypot.  When captivePortal is
// true, a simple landing page is served; otherwise all unknown requests are logged.
static void setupFakeAPHoneypot(const char* ssid, const char* password, bool captivePortal) {
  // Configure SoftAP
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ssid, password);
  IPAddress apIP = WiFi.softAPIP();
  // Use AsyncUDP DNS catcher to log queried hostnames and respond with the AP IP
  startDnsCatcher(apIP);

  // Register SoftAP event handler.  This callback fires when a station
  // associates, disconnects or sends a probe request to the AP.  We
  // register the handler every time the AP is started so that the
  // appropriate events are captured.  The handler lives outside of
  // this function.  Note: WiFi.onEvent() can accumulate multiple
  // handlers; that is acceptable in this context because each start
  // of a honeypot AP installs the same handler.
  WiFi.onEvent(onSoftAPEvent);
  // Clear any previous handlers and start HTTP server
  fakeApServer.reset();
  // Serve the root page.  Always log HTTP headers and inject a small
  // fingerprinting script that posts navigator info to /fp.  When
  // captivePortal=true we show a friendly welcome message; otherwise a
  // generic "It works" message is returned for unknown paths.  All
  // requests are logged via logHttp().
  fakeApServer.on("/", HTTP_GET, [captivePortal](AsyncWebServerRequest* request){
    // Log and alert for the root request
    hpLogHttp(request, "/");
    String html;
    if (captivePortal) {
      html = "<html><head><title>Welcome</title></head><body><h2>Welcome to this AP</h2><p>This is a fake network used for monitoring.</p>";
    } else {
      html = "<html><head><title>It works</title></head><body><h2>It works</h2>";
    }
    // Inject JS fingerprint: collect user agent, language, platform, timezone,
    // core count, memory and touch support then POST to /fp as JSON.
    html += "<script>(function(){try{const fp={ua:navigator.userAgent,lang:navigator.language,platform:navigator.platform,tz:(Intl.DateTimeFormat().resolvedOptions().timeZone||''),cores:(navigator.hardwareConcurrency||0),mem:(navigator.deviceMemory||0),touch:('ontouchstart' in window)};fetch('/fp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(fp)});}catch(e){}})();</script>";
    html += "</body></html>";
    request->send(200, "text/html", html);
  });
  // Catch all other paths: log request and return a simple page
  fakeApServer.onNotFound([](AsyncWebServerRequest* request){
    // Log and alert unknown paths to the honeypot HTTP logger
    hpLogHttp(request, request->url());
    request->send(200, "text/html", "<html><body><h2>Not found</h2></body></html>");
  });
  // Endpoint to receive fingerprint posts
  fakeApServer.on("/fp", HTTP_POST,
    [](AsyncWebServerRequest* request){
      request->send(200, "text/plain", "ok");
    },
    nullptr,
    [](AsyncWebServerRequest* request, uint8_t* data, size_t len, size_t, size_t){
      String ip = request->client()->remoteIP().toString();
      String payload = String((const char*)data, len);
      logEvent(String("FP,") + ip + "," + payload);
      hpPush("HONEYPOT_HTTP", "LOW",
             String("\"event\":\"fp\",\"ip\":\"") + ip + "\"");
    }
  );
  fakeApServer.begin();
  logEvent(String("FAKE_AP_STARTED,") + ssid);
}

// Process DNS requests for fake AP / credential honeypots
static void maintainFakeAP() {
  dnsServer.processNextRequest();
}

// Configure and start the credential honeypot (captive portal).
static void setupCredentialHoneypot(const char* ssid) {
  // Start the base fake AP in captive portal mode
  setupFakeAPHoneypot(ssid, "", true);
  // Override HTTP handlers for credential capture
  credentialServer.reset();
  // Serve login page and log headers + fingerprint.  The form posts to /login.
  credentialServer.on("/", HTTP_GET, [](AsyncWebServerRequest* request){
    // Log and alert credential landing page access
    hpLogHttp(request, "/");
    String html;
    html = "<html><head><title>Login</title></head><body>";
    html += "<h2>Access Internet</h2><form action='/login' method='post'>";
    html += "Username: <input type='text' name='u'><br>";
    html += "Password: <input type='password' name='p'><br>";
    html += "<input type='submit' value='Login'></form>";
    // Inject fingerprint script (same as fake AP)
    html += "<script>(function(){try{const fp={ua:navigator.userAgent,lang:navigator.language,platform:navigator.platform,tz:(Intl.DateTimeFormat().resolvedOptions().timeZone||''),cores:(navigator.hardwareConcurrency||0),mem:(navigator.deviceMemory||0),touch:('ontouchstart' in window)};fetch('/fp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(fp)});}catch(e){}})();</script>";
    html += "</body></html>";
    request->send(200, "text/html", html);
  });
  // Handle login submission
  credentialServer.on("/login", HTTP_POST, [](AsyncWebServerRequest* request){
    // Log and alert login attempt details
    hpLogHttp(request, "/login");
    if (request->hasParam("u", true) && request->hasParam("p", true)) {
      String user = request->getParam("u", true)->value();
      String pass = request->getParam("p", true)->value();
      String clientIp = request->client()->remoteIP().toString();
      // Log full credentials to SPIFFS/Serial
      logEvent(String("CRED_HONEYPOT_CREDENTIALS,") + clientIp + ",USER:" + user + ",PASS:" + pass);
      // Raise a high severity honeypot alert with masked username and IP
      hpPush("HP_CREDENTIAL", "HIGH",
             String("\"ip\":") + q(clientIp) + ",\"user\":" + q(maskMid(user)));
    }
    // Always display failure to avoid suspicion
    request->send(401, "text/html", "<html><body><h3>Authentication failed</h3><p>Please try again later.</p></body></html>");
  });
  // Fingerprint receiver
  credentialServer.on("/fp", HTTP_POST,
    [](AsyncWebServerRequest* req){
      req->send(200, "text/plain", "ok");
    },
    nullptr,
    [](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t, size_t){
      String ip = req->client()->remoteIP().toString();
      String payload = String((const char*)data, len);
      logEvent(String("FP,") + ip + "," + payload);
      hpPush("HONEYPOT_HTTP", "LOW",
             String("\"event\":\"fp\",\"ip\":\"") + ip + "\"");
    }
  );
  // Redirect all unknown paths back to root
  credentialServer.onNotFound([](AsyncWebServerRequest* request){
    // Log and alert unknown paths for the credential honeypot
    hpLogHttp(request, request->url());
    request->redirect("/");
  });
  credentialServer.begin();
  logEvent(String("CREDENTIAL_HONEYPOT_STARTED,") + ssid);
}

// Configure and start the Telnet/SSH honeypot
static void initTelnetHoneypot() {
  telnetServer.begin();
  sshServer.begin();
  telnetServer.setNoDelay(true);
  sshServer.setNoDelay(true);
  logEvent("TELNET_SSH_HONEYPOT_STARTED");
  // Reset session state
  for (int i = 0; i < MAX_SESSIONS; ++i) {
    sessions[i].client = WiFiClient();
    sessions[i].authenticated = false;
    sessions[i].awaitingUsername = false;
    sessions[i].awaitingPassword = false;
    sessions[i].username = "";
    sessions[i].password = "";
    sessions[i].currentLine = "";
  }
}

// Accept new connections for Telnet and SSH
static void handleNewTelnetConnections() {
  // Telnet connections
  if (telnetServer.hasClient()) {
    WiFiClient newClient = telnetServer.accept();
    logEvent(String("TELNET_NEW_CONNECTION,") + newClient.remoteIP().toString());
    // Raise a honeypot alert for a new telnet connection
    hpPush("HP_TELNET", "MEDIUM", String("\"ip\":\"") + newClient.remoteIP().toString() + "\"");
    for (int i = 0; i < MAX_SESSIONS; ++i) {
      if (!sessions[i].client) {
        sessions[i].client = newClient;
        sessions[i].authenticated = false;
        sessions[i].awaitingUsername = true;
        sessions[i].awaitingPassword = false;
        sessions[i].username = "";
        sessions[i].password = "";
        sessions[i].currentLine = "";
        sessions[i].client.print("\r\nWelcome to ESP32 telnet honeypot\r\nlogin: ");
        break;
      }
    }
    // No available slot
    if (newClient.connected() && !newClient.available() && newClient) {
      newClient.println("Server busy, try later.");
      newClient.stop();
    }
  }
  // SSH connections
  if (sshServer.hasClient()) {
    WiFiClient newClient = sshServer.accept();
    logEvent(String("SSH_NEW_CONNECTION,") + newClient.remoteIP().toString());
    // Raise a honeypot alert for a new SSH connection
    hpPush("HP_SSH", "MEDIUM", String("\"ip\":\"") + newClient.remoteIP().toString() + "\"");
    for (int i = 0; i < MAX_SESSIONS; ++i) {
      if (!sessions[i].client) {
        sessions[i].client = newClient;
        sessions[i].authenticated = false;
        sessions[i].awaitingUsername = true;
        sessions[i].awaitingPassword = false;
        sessions[i].username = "";
        sessions[i].password = "";
        sessions[i].currentLine = "";
        sessions[i].client.print("\r\nSSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\nlogin: ");
        break;
      }
    }
    if (newClient.connected() && !newClient.available() && newClient) {
      newClient.println("Server busy, try later.");
      newClient.stop();
    }
  }
}

// Process Telnet/SSH sessions and log credentials/commands
static void processTelnetSessions() {
  for (int i = 0; i < MAX_SESSIONS; ++i) {
    WiFiClient& client = sessions[i].client;
    if (!client) continue;
    if (!client.connected()) {
      logEvent(String("TELNET_CLIENT_DISCONNECTED,") + client.remoteIP().toString());
      client.stop();
      sessions[i] = SessionState();
      continue;
    }
    while (client.available()) {
      char c = client.read();
      if (c == '\r' || c == '\n') {
        String line = sessions[i].currentLine;
        sessions[i].currentLine = "";
        if (sessions[i].awaitingUsername) {
          sessions[i].username = line;
          sessions[i].awaitingUsername = false;
          sessions[i].awaitingPassword = true;
          client.print("Password: ");
        } else if (sessions[i].awaitingPassword) {
        sessions[i].password = line;
        sessions[i].awaitingPassword = false;
        // Log credentials to persistent storage
        logEvent(String("TELNET_CREDENTIALS,") + client.remoteIP().toString() + ",USER:" + sessions[i].username + ",PASS:" + sessions[i].password);
        // Raise a high severity honeypot alert (mask the username)
        hpPush("HP_TELNET", "HIGH",
               String("\"event\":\"CREDENTIALS\",\"ip\":\"") + client.remoteIP().toString() + "\",\"user\":\"" + maskMid(sessions[i].username) + "\"");
        sessions[i].authenticated = true;
        client.println("\r\nLast login: Thu Jan  1 00:00:00 on ttyS0");
        client.print("$ ");
        } else if (sessions[i].authenticated) {
          logEvent(String("TELNET_COMMAND,") + client.remoteIP().toString() + ",CMD:" + line);
          if (line == "exit" || line == "quit") {
            client.println("Bye.");
            client.stop();
            sessions[i] = SessionState();
            break;
          } else if (line.startsWith("cat")) {
            client.println("Permission denied");
          } else if (line == "help" || line == "?") {
            client.println("Available commands: whoami, uname, ls, pwd, exit");
          } else if (line == "whoami") {
            client.println(sessions[i].username);
          } else if (line == "pwd") {
            client.println(String("/home/") + sessions[i].username);
          } else if (line == "uname" || line == "uname -a") {
            client.println("Linux esp32 5.10.0-0-amd64 #1 SMP Debian 5.10.0 x86_64 GNU/Linux");
          } else {
            client.println("command not found");
          }
          client.print("$ ");
        }
      } else if (c == '\b' && sessions[i].currentLine.length() > 0) {
        sessions[i].currentLine.remove(sessions[i].currentLine.length() - 1);
      } else {
        sessions[i].currentLine += c;
      }
    }
  }
}

static void setupWiFiNet(){
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("[WiFi] Connecting to %s\n", WIFI_SSID);
  unsigned long start=millis();
  while (WiFi.status()!=WL_CONNECTED && millis()-start<15000){ delay(300); Serial.print("."); }
  Serial.println();
  if (WiFi.status()==WL_CONNECTED){
    wifiReady = true; apMode=false;
    Serial.printf("[WiFi] STA IP: %s\n", WiFi.localIP().toString().c_str());
    if (MDNS.begin(MDNS_NAME)){ MDNS.addService("http","tcp",80); Serial.printf("[mDNS] http://%s.local\n", MDNS_NAME); }
  } else {
    apMode = true; wifiReady = true;
    WiFi.mode(WIFI_AP);
    WiFi.softAP("Pandafense-AP","pandapass");
    Serial.printf("[WiFi] AP IP: %s\n", WiFi.softAPIP().toString().c_str());
  }
}

static void setupHTTP(){
  // Serve index: SPIFFS if present, else embedded
  server.on("/", HTTP_GET, [](AsyncWebServerRequest* req){
    if (SPIFFS.exists("/index.html")) req->send(SPIFFS, "/index.html", "text/html");
    else req->send_P(200, "text/html", indexHtml);
  });

  server.on("/api/status", HTTP_GET, handleStatus);
  server.on("/api/cmd", HTTP_POST,
    [](AsyncWebServerRequest* req){}, nullptr,
    [](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total){
      handleCmd(req, data, len);
    }
  );

  // RF API endpoints
  server.on("/rf/status", HTTP_GET, [](AsyncWebServerRequest* req){
    if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
    req->send(200,"application/json", RF::jsonStatus());
  });
  server.on("/rf/set", HTTP_POST,
    [](AsyncWebServerRequest* req){}, nullptr,
    [](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t, size_t){
      if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
      RF::applyTuning(req);
      req->send(200,"application/json","{\"ok\":true}");
    }
  );
  server.on("/rf/preset", HTTP_POST,
    [](AsyncWebServerRequest* req){}, nullptr,
    [](AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t, size_t){
      if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
      RF::applyPreset(req);
      req->send(200,"application/json","{\"ok\":true}");
    }
  );
  server.on("/rf/files", HTTP_GET, [](AsyncWebServerRequest* req){
    if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
    RF::sendFileList(req);
  });
  server.on("/rf/download", HTTP_GET, [](AsyncWebServerRequest* req){
    if(!tokenOK(req)){ req->send(401,"application/json","{\"error\":\"unauthorized\"}"); return; }
    if (!req->hasParam("file")) { req->send(400,"text/plain","missing file"); return; }
    String fn = req->getParam("file")->value();
    if(!fn.startsWith("/rf/")) fn = "/rf/" + fn;
    if (SPIFFS.exists(fn)) req->send(SPIFFS, fn, "application/octet-stream");
    else req->send(404,"text/plain","not found");
  });

  ws.onEvent([](AsyncWebSocket* srv, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t){
    if (t==WS_EVT_CONNECT){
      String hello = "{\"event\":\"hello\",\"payload\":"+jsonStatus()+"}";
      c->text(hello);
    }
  });
  server.addHandler(&ws);

  // Simple CORS for LAN testing
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

  server.onNotFound([](AsyncWebServerRequest* req){ req->send(404,"text/plain","Not found"); });
  server.begin();
  Serial.println("[HTTP] Server started");
}

// ============================================================================
// NEW: Start AP + Web server only when user picks "Yes" on Dashboard
// ============================================================================
static void startDashboard() {
  if (serverStarted) return;

  // Ensure filesystem is ready (for /index.html if present)
  if (!SPIFFS.begin(true)) Serial.println("[FS] mount failed");

  // Bring up AP for desktop access
  WiFi.mode(WIFI_AP);
  WiFi.softAP("Pandafense-AP", "pandapass");
  apMode    = true;
  wifiReady = true;

  // Optional mDNS in AP mode
  if (MDNS.begin(MDNS_NAME)) {
    MDNS.addService("http","tcp",80);
    Serial.printf("[mDNS] http://%s.local\n", MDNS_NAME);
  }

  // Start HTTP + WS once
  setupHTTP();
  serverStarted = true;

  // Show IP on OLED
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(WHITE); display.setCursor(0,0);
  display.print("AP IP: ");
  display.println(WiFi.softAPIP().toString());
  display.display();

  Serial.printf("[AP] SSID Pandafense-AP / pass pandapass\n");
  Serial.printf("[HTTP] http://%s/\n", WiFi.softAPIP().toString().c_str());
}

// ============================================================================
// Setup
// ============================================================================
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
  // Load settings (default soundOn = true)
  soundOff = prefs.getUChar("soundOff", 0) ? true : false;
  // Load overlay toggle (default overlay on)
  overlayOff = prefs.getUChar("overlayOff", 0) ? true : false;

  // Mount SPIFFS for honeypot logging (if not already mounted)
  if (!SPIFFS.begin(true)) {
    Serial.println("[FS] mount failed");
  }

  // Wi-Fi promiscuous config (disabled until a Wi-Fi detector is selected)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                   WIFI_PROMIS_FILTER_MASK_DATA |
                   WIFI_PROMIS_FILTER_MASK_CTRL
  };
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&packetHandler);
  esp_wifi_set_promiscuous(false);

  drawMain();

  // --- WebUI bring-up is gated by Dashboard now ---
  // (Intentionally NOT starting FS/WiFi/HTTP here)
  // setupFS();
  // setupWiFiNet();
  // setupHTTP();
  // pushStatus();
}

// ============================================================================
// Loop — button, menus, detectors, OLED faces + WebUI pushes
// ============================================================================
void loop() {
  unsigned long now = millis();
  // Expire honeypot alerts after the same duration used for other
  // detectors.  When a honeypot raises an alert, hpAlert becomes true
  // and remains true for ALERT_DURATION milliseconds.  After that,
  // hpAlert is cleared so that the face returns to normal unless
  // another alert fires.
  if (hpAlert && (now - hpAlertAt > ALERT_DURATION)) hpAlert = false;
  bool raw = digitalRead(BUTTON_PIN);

  // Debounce & button state
  if (raw != lastRaw) lastDebounce = now;
  if (now - lastDebounce > DEBOUNCE_DELAY) {
    if (raw == LOW  && pressStart == 0) pressStart = now;
    if (raw == HIGH && pressStart  > 0) {
      unsigned long held = now - pressStart;

      // MAIN menu
      if (menuLevel == MAIN) {
        if (held < LONG_PRESS_TIME) {
          mainIndex = (mainIndex + 1) % MAIN_COUNT;
          drawMain();
        } else {
          // Enter appropriate submenu
          inWifiSub     = (mainIndex == 0);
          inDashPrompt  = (mainIndex == 2);
          inSettingsSub = (mainIndex == 3);
          inRFSub       = (mainIndex == 4);
          // Honeypots submenu when index 5
          inHoneypotsSub= (mainIndex == 5);
          inRFSettings  = false;
          subIndex = 0; topRow = 0;
          menuLevel = SUBMENU;
          drawSub();
          pushStatus();
        }
      }

      // SUBMENU (Wi-Fi / Bluetooth / Dashboard prompt / Settings / RF)
      else if (menuLevel == SUBMENU) {
        // Short press: move selection
        if (held < LONG_PRESS_TIME) {
          int count;
          if (inSettingsSub) {
            count = 3;
          } else if (inDashPrompt) {
            count = 2;   // Yes/No
          } else if (inRFSettings) {
            count = 1;   // only back via long press
          } else if (inWifiSub) {
            count = WIFI_SUB_COUNT;
          } else if (inHoneypotsSub) {
            count = HP_SUB_COUNT;
          } else if (inRFSub) {
            count = RF_SUB_COUNT;
          } else {
            count = BT_SUB_COUNT;
          }

          // move selection (wrap)
          subIndex = (subIndex + 1) % count;

          // keep in view for Wi-Fi/BT/RF only
          if (!inSettingsSub && !inDashPrompt && !inRFSettings) {
            if (subIndex < topRow) topRow = subIndex;
            if (subIndex >= topRow + LIST_ROWS) topRow = subIndex - LIST_ROWS + 1;
          }
          drawSub();
        }
        // Long press: activate / toggle / back
        else {
          // NEW: Dashboard prompt Yes/No
          if (inDashPrompt) {
            if (subIndex == 0) {
              // YES → start AP + server
              startDashboard();
              pushStatus();
            }
            // In both Yes/No cases, go back to MAIN
            inDashPrompt = false;
            menuLevel = MAIN;
            drawMain();
            pushStatus();
          }
          // SETTINGS submenu
          else if (inSettingsSub) {
            // index 0 -> toggle sound; index 1 -> toggle overlay; index 2 -> back to MAIN
            if (subIndex == 0) {
              soundOff = !soundOff;
              saveSettings();
              drawSub(); // reflect new On/Off
              pushStatus();
            } else if (subIndex == 1) {
              overlayOff = !overlayOff;
              saveSettings();
              drawSub(); // reflect new On/Off
              pushStatus();
            } else {
              inSettingsSub = false;
              menuLevel = MAIN;
              drawMain();
              pushStatus();
            }
          }
          // RF preset/tuning view: long press returns to RF submenu
          else if (inRFSettings) {
            inRFSettings = false;
            menuLevel = SUBMENU;
            drawSub();
            pushStatus();
          }
          // Wi-Fi / BT / RF submenus
          else {
            int count;
            if (inWifiSub) {
              count = WIFI_SUB_COUNT;
            } else if (inHoneypotsSub) {
              count = HP_SUB_COUNT;
            } else if (inRFSub) {
              count = RF_SUB_COUNT;
            } else {
              count = BT_SUB_COUNT;
            }
            if (subIndex == count - 1) {
              // "Menu" entry -> back to MAIN
              if (inWifiSub) { inWifiSub = false; }
              if (inRFSub) { inRFSub = false; }
              if (inHoneypotsSub) { inHoneypotsSub = false; }
              menuLevel = MAIN;
              drawMain();
              pushStatus();
            } else if (inRFSub && subIndex == 6) {
              // "Presets / Tuning" entry
              inRFSettings = true;
              drawSub();
            } else {
              // stop everything first
              esp_wifi_set_promiscuous(false);
              BLEMON::stop();
              BLEJAM::stop();
              RF::stop();
              // Call stopAllDetectors() to shut down any active honeypot
              // servers (fake AP, telnet, credential or beacon) and reset
              // internal state.  Without this call, selecting a new
              // honeypot could leave the previous one running.
              stopAllDetectors();

              if (inWifiSub) {
                // map Wi-Fi index → mode (contiguous)
                mode = Mode(MODE_DEAUTH + subIndex);
                esp_wifi_set_promiscuous(true);
              } else if (inHoneypotsSub) {
                // Start the selected honeypot
                if (subIndex == 0) {
                  setupFakeAPHoneypot("Panda_HP_AP", "", false);
                  mode = MODE_HP_FAKE_AP;
                } else if (subIndex == 1) {
                  initTelnetHoneypot();
                  mode = MODE_HP_TELNET;
                } else if (subIndex == 2) {
                  setupCredentialHoneypot("FreeWifi-HP");
                  mode = MODE_HP_CREDENTIAL;
                } else if (subIndex == 3) {
                  initBleBeaconHoneypot("PandaFense-BLE");
                  mode = MODE_HP_BLE_BEACON;
                }
              } else if (inRFSub) {
                // map RF index → mode (0-5 detectors)
                mode = Mode(MODE_RF_BANDSCAN + subIndex);
                RF::start(mode);
              } else {
                // BLE: first 10 are scan-only detectors, then Jam
                if (subIndex <= 9) {
                  mode = Mode(MODE_BT_ADV_FLOOD + subIndex);
                  BLEMON::start();
                } else if (subIndex == 10) {
                  mode = MODE_BT_JAM;
                  BLEJAM::start();
                }
              }
              menuLevel = ACTIVE;
              pushStatus();
            }
          }
        }
      }

      // ACTIVE mode (long press to stop and go back to MAIN)
      else if (menuLevel == ACTIVE) {
        if (held >= LONG_PRESS_TIME) {
          if (mode >= MODE_DEAUTH && mode <= MODE_BCAST_DATA) esp_wifi_set_promiscuous(false);
          if (mode >= MODE_BT_ADV_FLOOD && mode <= MODE_BT_RSSI_TELEPORT) BLEMON::stop();
          if (mode == MODE_BT_JAM) BLEJAM::stop();
          if (mode >= MODE_RF_BANDSCAN && mode <= MODE_RF_IDS) RF::stop();
          mode = MODE_NONE; menuLevel = MAIN; drawMain();
          pushStatus();
        }
      }

      pressStart = 0;
    }
  }
  lastRaw = raw;

  // ACTIVE: run the selected engine and draw the panda
  if (menuLevel == ACTIVE) {

    // Wi-Fi engine
    if (mode >= MODE_DEAUTH && mode <= MODE_BCAST_DATA) {
      if (now - lastChannelHop > CHANNEL_HOP_INTERVAL) {
        lastChannelHop = now;
        currentChannel = (currentChannel % 13) + 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      }
      if (deauthDetected    && now - lastDeauthTime    > ALERT_DURATION) deauthDetected    = false;
      if (rogueDetected     && now - lastRogueTime     > ROGUE_TIMEOUT)  rogueDetected     = false;
      if (arpDetected       && now - lastARPTime       > ARP_TIMEOUT)    arpDetected       = false;
      if (beaconDetected    && now - lastBeaconTime    > ALERT_DURATION) beaconDetected    = false;

      if (disassocDetected  && now - lastDisassocTime  > DISASSOC_TIMEOUT)    disassocDetected  = false;
      if (probeFloodDetected&& now - lastProbeTime     > ALERT_DURATION)       probeFloodDetected= false;
      if (rtsctsDetected    && now - lastRtsCtsTime    > ALERT_DURATION)       rtsctsDetected    = false;
      if (eapolStormDetected&& now - lastEapolTime     > ALERT_DURATION)       eapolStormDetected= false;
      if (csaDetected       && now - lastCsaTime       > ALERT_DURATION)       csaDetected       = false;
      if (spoofMgmtDetected && now - lastSpoofTime     > SPOOF_TIMEOUT)        spoofMgmtDetected = false;
      if (beaconAnomDetected&& now - lastBeaconAnomTime> ALERT_DURATION)       beaconAnomDetected= false;
      if (wpsSpamDetected   && now - lastWpsTime       > ALERT_DURATION)       wpsSpamDetected   = false;
      if (rsnMismatchDetected&&now - lastRsnMismatchTime> RSN_MISMATCH_TIMEOUT)rsnMismatchDetected= false;
      if (bcastDataDetected && now - lastBcastDataTime > ALERT_DURATION)       bcastDataDetected = false;
    }

    // BLE scan-only engine
    else if (mode >= MODE_BT_ADV_FLOOD && mode <= MODE_BT_RSSI_TELEPORT) {
      BLEMON::tick();
    }

    // BLE jam engine
    else if (mode == MODE_BT_JAM) {
      BLEJAM::tick();
      if (bleJamDetected && now - lastBleJamTime > ALERT_DURATION) bleJamDetected = false;
    }

    // RF engine
    else if (mode >= MODE_RF_BANDSCAN && mode <= MODE_RF_IDS) {
      RF::tick();
    }

    // Decide alarm + face
    bool alarm =
      deauthDetected || rogueDetected || arpDetected || beaconDetected ||
      disassocDetected || probeFloodDetected || rtsctsDetected || eapolStormDetected ||
      csaDetected || spoofMgmtDetected || beaconAnomDetected || wpsSpamDetected ||
      rsnMismatchDetected || bcastDataDetected ||
      BLEMON::anyAlert() || bleJamDetected || (mode == MODE_RF_IDS && RF::isIdsAlert()) ||
      hpAlert;

    digitalWrite(RED_LED_PIN,   alarm ? HIGH : LOW);
    digitalWrite(GREEN_LED_PIN, alarm ? LOW  : HIGH);
    // Respect the sound setting (mute when soundOff == true)
    digitalWrite(BUZZER_PIN,    (alarm && !soundOff) ? HIGH : LOW);

    // Render either the animated panda or textual alerts depending on overlayOff
    if (overlayOff) {
      // Display textual status instead of panda graphics
      display.clearDisplay();
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.setCursor(0, 0);
      // Show recent alert if alarm is active or within a grace period
      if (alarm || (now - lastAlertTs <= ALERT_TEXT_DURATION)) {
        // Print the detector name and severity on separate lines
        display.print("Alert: ");
        display.println(lastAlertName);
        display.print("Severity: ");
        display.println(lastAlertSev);
      } else {
        // Otherwise show current mode and monitoring status
        display.print("Mode: ");
        display.println(modeName());
        display.setCursor(0, ROW_H);
        display.print("Monitoring...");
      }
      display.display();
    } else {
      // Original animated panda UI
      if (alarm) {
        static unsigned long lastTongueAnim = 0;
        static bool tongueFlip = false;
        if (now - lastTongueAnim >= TONGUE_ANIM_MS) { lastTongueAnim = now; tongueFlip = !tongueFlip; }
        showDeadFaceAnimated(tongueFlip);
      } else {
        static unsigned long lastAnim = 0; static int frame = 0;
        if (now - lastAnim >= 3000) { lastAnim = now; frame = (frame + 1) % NUM_FRAMES; }
        showHappyFaceAnimated(frame);
      }
    }

    // Honeypot maintenance: process DNS and Telnet/SSH activity when in honeypot modes
    if (mode == MODE_HP_FAKE_AP || mode == MODE_HP_CREDENTIAL) {
      maintainFakeAP();
    }
    if (mode == MODE_HP_TELNET) {
      handleNewTelnetConnections();
      processTelnetSessions();
    }

    // Small render throttle
    delay(50);
  }

  // ===================== WebUI integration in loop ======================
  // Maintain WS clients (safe even if server hasn't started yet)
  ws.cleanupClients();

  // Rising-edge push for Wi-Fi alerts
  static bool p_deauth=false, p_rogue=false, p_arp=false, p_beacon=false;
  static bool p_disassoc=false, p_probe=false, p_rtscts=false, p_eapol=false, p_csa=false, p_spoof=false, p_beacAnom=false, p_wps=false, p_rsn=false, p_bcast=false;

  auto edgePush = [&](bool cur, bool& prev, const char* name, const char* sev, const String& kv){
    if (cur && !prev) pushAlert(name, sev, kv);
    prev = cur;
  };

  edgePush(deauthDetected,     p_deauth,   "DEAUTH",       "HIGH",   "\"chan\":"+String(currentChannel));
  edgePush(rogueDetected,      p_rogue,    "ROGUE_AP",     "MEDIUM", "\"chan\":"+String(currentChannel));
  edgePush(arpDetected,        p_arp,      "ARP",          "MEDIUM", "\"note\":\"multi-mac same IP\"");
  edgePush(beaconDetected,     p_beacon,   "BEACON",       "LOW",    "\"note\":\"per-SSID spike\"");
  edgePush(disassocDetected,   p_disassoc, "DISASSOC",     "LOW",    "\"note\":\"many disassoc\"");
  edgePush(probeFloodDetected, p_probe,    "PROBE",        "LOW",    "\"note\":\"probe flood\"");
  edgePush(rtsctsDetected,     p_rtscts,   "RTSCTS",       "LOW",    "\"note\":\"RTS/CTS flood\"");
  edgePush(eapolStormDetected, p_eapol,    "EAPOL",        "LOW",    "\"note\":\"EAPOL storm\"");
  edgePush(csaDetected,        p_csa,      "CSA",          "LOW",    "\"note\":\"freq switch\"");
  edgePush(spoofMgmtDetected,  p_spoof,    "SPOOFEDMGMT",  "LOW",    "\"note\":\"mgmt from unknown\"");
  edgePush(beaconAnomDetected, p_beacAnom, "BEACON_ANOM",  "LOW",    "\"note\":\"bad IEs/empty SSID\"");
  edgePush(wpsSpamDetected,    p_wps,      "WPS",          "LOW",    "\"note\":\"WPS vendor IE\"");
  edgePush(rsnMismatchDetected,p_rsn,      "RSN_MISMATCH", "LOW",    "\"note\":\"open+RSN mix\"");
  edgePush(bcastDataDetected,  p_bcast,    "BCAST_DATA",   "LOW",    "\"note\":\"broadcast spike\"");

  // Per-type BLE edges
  static uint32_t prevBle = 0;
  if (mode >= MODE_BT_ADV_FLOOD && mode <= MODE_BT_RSSI_TELEPORT) {
    uint32_t m = BLEMON::snapshotAlerts();
    uint32_t newBits = m & ~prevBle;
    auto push = [&](uint32_t bit, const char* name){
      if (newBits & bit) pushAlert(name, "LOW", "\"note\":\"BLE anomaly\"");
    };
    push(BLEMON::AB_ADV_FLOOD,      "BT_ADV_FLOOD");
    push(BLEMON::AB_UUID_FLOOD,     "BT_UUID_FLOOD");
    push(BLEMON::AB_ADDR_HOP,       "BT_ADDR_HOP");
    push(BLEMON::AB_SERVICE_SPOOF,  "BT_SERVICE_SPOOF");
    push(BLEMON::AB_MFR_STORM,      "BT_MFR_STORM");
    push(BLEMON::AB_SCANRSP_ABUSE,  "BT_SCANRSP_ABUSE");
    push(BLEMON::AB_INTERVAL_ANOM,  "BT_INTERVAL_ANOM");
    push(BLEMON::AB_REPLAY_CLONE,   "BT_REPLAY_CLONE");
    push(BLEMON::AB_NAME_SQUAT,     "BT_NAME_SQUAT");
    push(BLEMON::AB_RSSI_TELEPORT,  "BT_RSSI_TELEPORT");
    prevBle = m;
  } else {
    prevBle = 0;
  }

}