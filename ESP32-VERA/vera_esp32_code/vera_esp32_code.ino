/*=================================================================
  VERA CYBER DEFENSE DASHBOARD  v2.0
  -----------------------------------------------------------------
  Target Hardware : Waveshare ESP32-S3-Touch-LCD-7B
    - MCU         : ESP32-S3-WROOM-1-N16R8 (16MB Flash, 8MB Octal PSRAM)
    - Display     : 7.0" 1024x600 RGB Parallel LCD (RGB565, 30MHz PCLK)
    - Touch       : GT911 Capacitive Touch Controller (I2C SDA=8, SCL=9, INT=4)
    - I/O Expander: CH32V003 MCU via I2C (0x24) - Backlight PWM, Resets
    - Storage     : MicroSD via hardware SDMMC 1-bit mode (CLK=12, CMD=11, D0=13)
    - GUI         : LVGL v8 with Dual Dark/Light Theme Switching

  Exposes five decoy surfaces (ICMP, Telnet, SSH, FTP, HTTP), records
  every probe, credential, and shell payload command, and displays a
  live interactive Cyber SOC Dashboard on the 7" capacitive touch screen.
  Includes a live browser admin dashboard on port 8080.

  DEFENSIVE / RESEARCH USE ONLY.
=================================================================*/

#include <Arduino.h>
#include <WiFi.h>
#include <FS.h>
#include <SD_MMC.h>
#include <time.h>
#include <lvgl.h>
#include <esp_wifi.h>

/* Safe font fallbacks in case custom Montserrat sizes are disabled in lv_conf.h */
#ifndef LV_FONT_MONTSERRAT_10
#define LV_FONT_MONTSERRAT_10 0
#endif
#if !LV_FONT_MONTSERRAT_10
#define lv_font_montserrat_10 lv_font_montserrat_14
#endif

#ifndef LV_FONT_MONTSERRAT_12
#define LV_FONT_MONTSERRAT_12 0
#endif
#if !LV_FONT_MONTSERRAT_12
#define lv_font_montserrat_12 lv_font_montserrat_14
#endif

#ifndef LV_FONT_MONTSERRAT_16
#define LV_FONT_MONTSERRAT_16 0
#endif
#if !LV_FONT_MONTSERRAT_16
#define lv_font_montserrat_16 lv_font_montserrat_14
#endif

#ifndef LV_FONT_MONTSERRAT_28
#define LV_FONT_MONTSERRAT_28 0
#endif
#if !LV_FONT_MONTSERRAT_28
#define lv_font_montserrat_28 lv_font_montserrat_14
#endif

/* Board-specific hardware drivers */
#include "esp_lv_adapter_arduino.h"
#include "rgb_lcd_port.h"
#include "io_extension.h"
#include "touch.h"
#include "gt911.h"

/* lwIP raw layer for ICMP ping interception and ARP MAC address resolution */
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"

/*=================== 1. USER SETTINGS ==========================*/
static const char *WIFI_SSID = "ESPTEST";
static const char *WIFI_PASS = "uxoricide19950804";

// Hardware storage mount flag (declared early for config loaders)
bool sdOk = false;

// Active mutable Wi-Fi settings (persisted in MicroSD /wifi.cfg to prevent SPI Flash cache disables)
char curWifiSsid[64] = "ESPTEST";
char curWifiPass[64] = "uxoricide19950804";

void saveWifiConfig(const char *s, const char *pass) {
  if (!s || !s[0]) return;
  strncpy(curWifiSsid, s, sizeof(curWifiSsid) - 1);
  curWifiSsid[sizeof(curWifiSsid) - 1] = '\0';
  if (pass) {
    strncpy(curWifiPass, pass, sizeof(curWifiPass) - 1);
    curWifiPass[sizeof(curWifiPass) - 1] = '\0';
  } else {
    curWifiPass[0] = '\0';
  }

  // Persist to MicroSD if mounted (SDMMC does not disable CPU cache)
  if (sdOk) {
    fs::File f = SD_MMC.open("/wifi.cfg", FILE_WRITE);
    if (f) {
      f.println(curWifiSsid);
      f.println(curWifiPass);
      f.close();
      Serial.printf("[WIFI] Credentials saved to SD: %s\n", curWifiSsid);
    }
  }
}

void loadWifiConfig() {
  if (sdOk && SD_MMC.exists("/wifi.cfg")) {
    fs::File f = SD_MMC.open("/wifi.cfg", FILE_READ);
    if (f) {
      String s = f.readStringUntil('\n');
      s.trim();
      String p = f.readStringUntil('\n');
      p.trim();
      f.close();
      if (s.length() > 0) {
        strncpy(curWifiSsid, s.c_str(), sizeof(curWifiSsid) - 1);
        curWifiSsid[sizeof(curWifiSsid) - 1] = '\0';
        strncpy(curWifiPass, p.c_str(), sizeof(curWifiPass) - 1);
        curWifiPass[sizeof(curWifiPass) - 1] = '\0';
        Serial.printf("[WIFI] Loaded credentials from SD: %s\n", curWifiSsid);
        return;
      }
    }
  }
  strncpy(curWifiSsid, WIFI_SSID, sizeof(curWifiSsid) - 1);
  curWifiSsid[sizeof(curWifiSsid) - 1] = '\0';
  strncpy(curWifiPass, WIFI_PASS, sizeof(curWifiPass) - 1);
  curWifiPass[sizeof(curWifiPass) - 1] = '\0';
}

// Decoy identity VERA pretends to be.
static const char *FAKE_HOST = "DVR-CAM-04";

// Secret key for your real admin web dashboard on port 8080.
#define ADMIN_KEY "change-this-key"

// Timezone (Dhaka = UTC+6; change to match your location)
static const long GMT_OFFSET_SEC = 6 * 3600;
static const int  DST_OFFSET_SEC = 0;

// Optional hardware alert LED / Buzzer. -1 = disabled.
#define ALERT_PIN     -1
#define ALERT_MS      60

// Allow attackers into a fake BusyBox shell after 2 failed attempts to harvest payloads.
#define FAKE_SHELL    true

// MicroSD card pins (Waveshare ESP32-S3-Touch-LCD-7B SDMMC 1-bit mode)
#define SDMMC_CLK     12
#define SDMMC_CMD     11
#define SDMMC_D0      13

// Set to true if you have a MicroSD card inserted; false to run in high-speed RAM mode.
#define USE_SD_CARD   false

#define LOG_PATH      "/vera.log"
#define STATE_PATH    "/state.bin"

// Quiet window for repeated pings from the same IP (ms)
#define PING_QUIET_MS 8000

// Rate limit between state saves (ms)
#define STATE_SAVE_MS 20000

// Default screen backlight level (10-100%)
#define DEFAULT_BACKLIGHT 90
/*===============================================================*/


/*=================== 2. TYPES AND GLOBALS ======================*/
bool isDarkMode = true;             // Theme state (Dark vs Light)
uint8_t currentBrightness = DEFAULT_BACKLIGHT;

/* ---- Battery Telemetry & State ---- */
struct BatteryInfo {
  float    voltage;
  int      percent;
  bool     present;
  bool     charging;
  uint16_t rawAdc;
  char     status[32];
  char     pillText[32];
};
BatteryInfo curBat = {0.0f, 0, false, false, 0, "Initializing", "--"};

WiFiServer srvTelnet(23);
WiFiServer srvSSH(22);
WiFiServer srvFTP(21);
WiFiServer srvHTTP(80);
WiFiServer srvAdmin(8080);

/* ---- Threat Counters ---- */
struct Stats {
  uint32_t telnet;
  uint32_t ssh;
  uint32_t ftp;
  uint32_t http;
  uint32_t ping;
  uint32_t total;
  uint32_t creds;
  uint32_t payloads;
  uint32_t scans;
  uint32_t boots;
};
Stats st;

/* ---- Unique IP Tracking & Port-Scan Detector ---- */
#define MAX_IPS 50
struct IpRec {
  uint32_t ip;
  char     mac[18];
  uint8_t  mask;        // 1=telnet, 2=ssh, 4=ftp, 8=http, 16=icmp
  bool     flagged;
  uint32_t lastPing;
};
IpRec   ipTab[MAX_IPS];
uint8_t ipCount = 0;

/* ---- Captured Credentials & Payloads Store ---- */
#define MAX_CAPTURED 30
struct CapturedCred {
  char time[12];
  char svc[8];
  char ip[16];
  char user[24];
  char pass[24];
};
CapturedCred credTab[MAX_CAPTURED];
uint8_t credCount = 0;

struct CapturedPayload {
  char time[12];
  char svc[8];
  char ip[16];
  char cmd[64];
};
CapturedPayload payloadTab[MAX_CAPTURED];
uint8_t payloadCount = 0;

/* ---- ICMP Queue ---- */
#define ICMP_Q 20
volatile uint32_t icmpQ[ICMP_Q];
volatile uint8_t  icmpHead = 0;
volatile uint8_t  icmpTail = 0;
portMUX_TYPE      icmpMux = portMUX_INITIALIZER_UNLOCKED;

/* ---- Persistence ---- */
#define STATE_MAGIC 0x484E5037UL      /* 'HNP7' */
struct StateBlob {
  uint32_t magic;
  Stats    st;
  uint8_t  ipCount;
  IpRec    ipTab[MAX_IPS];
  bool     darkMode;
  uint8_t  brightness;
  uint32_t sum;
};
bool     stateDirty    = false;
uint32_t lastStateSave = 0;
bool     ntpConfigured = false;

/* ---- Session State ---- */
struct Session {
  WiFiClient c;
  bool       active;
  uint8_t    stage;      // 1=user, 2=pass, 3=shell
  uint8_t    tries;
  uint32_t   last;
  String     line;
  String     user;
  IPAddress  ip;
};
Session tn;
Session ft;

/* ---- Event Log Queue for UI ---- */
#define MAX_UI_EVENTS 50
struct LogEntry {
  char time[12];
  char svc[10];
  char ip[18];
  char mac[18];
  char detail[70];
  uint32_t color;
  bool isAlert;
};
LogEntry logEntries[MAX_UI_EVENTS];
uint8_t  logCount = 0;

/* ---- Forward Declarations ---- */
void timeStr(char *out, size_t n, bool full);
void alertPulse();
String clean(const String &in, size_t cap = 64);
String getMacForIp(IPAddress ip);
void touchIp(IPAddress ip, uint8_t bit, bool &isNewIp, bool &isScan);
bool mountSD();
void saveState(bool force);
bool loadState();
void logEvent(const char *svc, IPAddress ip, const String &detail, uint32_t colourHex, bool isAlert, bool loud = false);
void logCreds(const char *svc, IPAddress ip, const String &u, const String &p);
void checkPayload(const char *svc, IPAddress ip, const String &cmd);
void startIcmpWatch();
void serviceIcmp();
void handleTelnet();
void handleSSH();
void handleFTP();
void handleHTTP();
void handleAdmin();

/* UI Functions */
void showSplash();
void createUI();
void applyTheme(bool dark);
void updateDashboardMetrics();
void addEventToUI(const LogEntry &e);
void updateIpTableUI();
void updateLootUI();
void updateStatusBarUI();
void updateBatteryTelemetry();
uint32_t blobSum(const StateBlob &b);
bool readLine(Session &s);

/* Helper for WiFiServer accept */
static inline WiFiClient srvAccept(WiFiServer &s) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && (ESP_ARDUINO_VERSION_MAJOR >= 3)
  return s.accept();
#else
  return s.available();
#endif
}

void updateBatteryTelemetry() {
  uint32_t sum = 0;
  const int SAMPLES = 8;
  for (int i = 0; i < SAMPLES; i++) {
    sum += IO_EXTENSION_Adc_Input();
    delayMicroseconds(200);
  }
  curBat.rawAdc = sum / SAMPLES;

  // Waveshare ESP32-S3-Touch-LCD-7B calculation:
  // CH32V003 10-bit ADC (0..1023), 3.3V reference, 3:1 resistor divider:
  float rawV = (float)curBat.rawAdc * (3.0f * 3.3f / 1023.0f);

  if (curBat.voltage <= 0.5f) {
    curBat.voltage = rawV;
  } else {
    curBat.voltage = (curBat.voltage * 0.75f) + (rawV * 0.25f);
  }

  if (curBat.voltage < 2.50f) {
    curBat.present = false;
    curBat.charging = false;
    curBat.percent = 0;
    snprintf(curBat.status, sizeof(curBat.status), "USB Power (No Batt)");
    snprintf(curBat.pillText, sizeof(curBat.pillText), "⚡ USB (5.0V)");
  } else {
    curBat.present = true;
    // Single cell Li-ion discharge range: 3.40V (empty) to 4.20V (full)
    float p = (curBat.voltage - 3.40f) / (4.20f - 3.40f) * 100.0f;
    if (p < 0.0f) p = 0.0f;
    if (p > 100.0f) p = 100.0f;
    curBat.percent = (int)(p + 0.5f);

    if (curBat.voltage >= 4.18f) {
      curBat.charging = false;
      snprintf(curBat.status, sizeof(curBat.status), "Battery Full / Plugged");
      snprintf(curBat.pillText, sizeof(curBat.pillText), "⚡ 100%% (%.2fV)", curBat.voltage);
    } else if (curBat.voltage >= 4.02f) {
      curBat.charging = true;
      snprintf(curBat.status, sizeof(curBat.status), "Charging (CS8501)");
      snprintf(curBat.pillText, sizeof(curBat.pillText), "⚡ CHG %d%% (%.2fV)", curBat.percent, curBat.voltage);
    } else if (curBat.percent <= 15) {
      curBat.charging = false;
      snprintf(curBat.status, sizeof(curBat.status), "Low Battery Warning");
      snprintf(curBat.pillText, sizeof(curBat.pillText), "🪫 %d%% (%.2fV)", curBat.percent, curBat.voltage);
    } else {
      curBat.charging = false;
      snprintf(curBat.status, sizeof(curBat.status), "On Battery (Discharging)");
      snprintf(curBat.pillText, sizeof(curBat.pillText), "🔋 %d%% (%.2fV)", curBat.percent, curBat.voltage);
    }
  }
}


/*=================== 3. SMALL HELPERS ==========================*/
void timeStr(char *out, size_t n, bool full) {
  struct tm t;
  if (getLocalTime(&t, 5)) {
    strftime(out, n, full ? "%Y-%m-%d %H:%M:%S" : "%H:%M:%S", &t);
    return;
  }
  // Fallback to active system uptime if NTP has not yet synchronized
  uint32_t s = millis() / 1000;
  uint32_t hrs = s / 3600;
  uint32_t mins = (s % 3600) / 60;
  uint32_t secs = s % 60;
  if (full) {
    snprintf(out, n, "UP %02u:%02u:%02u", hrs, mins, secs);
  } else {
    snprintf(out, n, "%02u:%02u:%02u", hrs, mins, secs);
  }
}

void alertPulse() {
#if ALERT_PIN >= 0
  digitalWrite(ALERT_PIN, HIGH);
  delay(ALERT_MS);
  digitalWrite(ALERT_PIN, LOW);
#endif
}

String clean(const String &in, size_t cap) {
  String o;
  for (size_t i = 0; i < in.length() && o.length() < cap; i++) {
    char c = in[i];
    if (c >= 32 && c <= 126) o += c;
  }
  o.trim();
  return o;
}

String escapeJson(const String &s) {
  String o;
  o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"') o += "\\\"";
    else if (c == '\\') o += "\\\\";
    else if (c == '\r') o += "\\r";
    else if (c == '\n') o += "\\n";
    else if (c == '\t') o += "\\t";
    else if ((uint8_t)c < 32) o += ' ';
    else o += c;
  }
  return o;
}

/* Resolve MAC address for an IP from lwIP ARP table cache */
String getMacForIp(IPAddress ip) {
  if (ip == IPAddress(0, 0, 0, 0)) return String("--");
  if (ip == WiFi.localIP()) return WiFi.macAddress();

  char buf[20] = "--";
  ip4_addr_t ipaddr;
  ipaddr.addr = (uint32_t)ip;
  struct eth_addr *eth_ret = nullptr;
  const ip4_addr_t *ip_ret = nullptr;
  struct netif *netif = nullptr;

  LOCK_TCPIP_CORE();
  NETIF_FOREACH(netif) {
    ssize_t idx = etharp_find_addr(netif, &ipaddr, &eth_ret, &ip_ret);
    if (idx >= 0 && eth_ret != nullptr) {
      snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
               eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
               eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
      break;
    }
  }
  UNLOCK_TCPIP_CORE();

  return String(buf);
}

void touchIp(IPAddress ip, uint8_t bit, bool &isNewIp, bool &isScan) {
  uint32_t v = (uint32_t)ip;
  isNewIp = false;
  isScan  = false;
  for (uint8_t i = 0; i < ipCount; i++) {
    if (ipTab[i].ip == v) {
      ipTab[i].mask |= bit;
      if (ipTab[i].mac[0] == '\0' || strcmp(ipTab[i].mac, "--") == 0) {
        String m = getMacForIp(ip);
        if (m != "--") {
          strncpy(ipTab[i].mac, m.c_str(), sizeof(ipTab[i].mac) - 1);
          ipTab[i].mac[sizeof(ipTab[i].mac) - 1] = '\0';
        }
      }
      uint8_t m = ipTab[i].mask;
      uint8_t n = 0;
      while (m) { n += m & 1; m >>= 1; }
      if (n >= 3 && !ipTab[i].flagged) {
        ipTab[i].flagged = true;
        isScan = true;
        st.scans++;
      }
      return;
    }
  }
  if (ipCount < MAX_IPS) {
    ipTab[ipCount].ip       = v;
    String m = getMacForIp(ip);
    strncpy(ipTab[ipCount].mac, m.c_str(), sizeof(ipTab[ipCount].mac) - 1);
    ipTab[ipCount].mac[sizeof(ipTab[ipCount].mac) - 1] = '\0';
    ipTab[ipCount].mask     = bit;
    ipTab[ipCount].flagged  = false;
    ipTab[ipCount].lastPing = 0;
    ipCount++;
    isNewIp = true;
  }
}


/*=================== 4. SD CARD (SDMMC 1-BIT) ===================*/
bool mountSD() {
#if !USE_SD_CARD
  Serial.println("[SD] MicroSD disabled (USE_SD_CARD=false). Operating in RAM mode.");
  return false;
#else
  if (!SD_MMC.setPins(SDMMC_CLK, SDMMC_CMD, SDMMC_D0)) {
    Serial.println("SD_MMC: setPins failed");
    return false;
  }
  // Mount 1-bit mode, do not format if mount fails
  if (!SD_MMC.begin("/sdcard", true, false)) {
    Serial.println("SD_MMC: mount failed or card missing");
    SD_MMC.end();
    return false;
  }
  uint8_t cardType = SD_MMC.cardType();
  if (cardType == CARD_NONE) {
    Serial.println("SD_MMC: no card detected");
    SD_MMC.end();
    return false;
  }
  uint64_t mb = SD_MMC.cardSize() / (1024ULL * 1024ULL);
  Serial.printf("SD_MMC: mounted successfully, %llu MB\n", mb);
  return true;
#endif
}


/*=================== 5. PERSISTENT STATE =======================*/
uint32_t blobSum(const StateBlob &b) {
  const uint8_t *p = (const uint8_t *)&b;
  size_t n = sizeof(StateBlob) - sizeof(uint32_t);
  uint32_t s = 0x5678;
  for (size_t i = 0; i < n; i++) s = s * 31 + p[i];
  return s;
}

void saveState(bool force) {
  if (!sdOk) return;
  if (!force && !stateDirty) return;
  if (!force && (millis() - lastStateSave) < STATE_SAVE_MS) return;

  StateBlob b;
  memset(&b, 0, sizeof(b));
  b.magic      = STATE_MAGIC;
  b.st         = st;
  b.ipCount    = ipCount;
  memcpy(b.ipTab, ipTab, sizeof(ipTab));
  b.darkMode   = isDarkMode;
  b.brightness = currentBrightness;
  b.sum        = blobSum(b);

  fs::File f = SD_MMC.open(STATE_PATH, FILE_WRITE);
  if (!f) return;
  f.write((uint8_t *)&b, sizeof(b));
  f.close();

  lastStateSave = millis();
  stateDirty    = false;
}

bool loadState() {
  if (!sdOk) return false;
  fs::File f = SD_MMC.open(STATE_PATH, FILE_READ);
  if (!f) return false;
  if (f.size() != sizeof(StateBlob)) { f.close(); return false; }

  StateBlob b;
  f.read((uint8_t *)&b, sizeof(b));
  f.close();

  if (b.magic != STATE_MAGIC) return false;
  if (b.sum   != blobSum(b))  return false;

  st      = b.st;
  ipCount = (b.ipCount > MAX_IPS) ? MAX_IPS : b.ipCount;
  memcpy(ipTab, b.ipTab, sizeof(ipTab));
  isDarkMode = b.darkMode;
  if (b.brightness >= 10 && b.brightness <= 100) currentBrightness = b.brightness;
  return true;
}


/*=================== 6. LOGGING ================================*/
void fileLog(const char *svc, IPAddress ip, const char *mac, const char *detail) {
  if (!sdOk) return;
  fs::File f = SD_MMC.open(LOG_PATH, FILE_APPEND);
  if (!f) return;
  char ts[24];
  timeStr(ts, sizeof(ts), true);
  f.printf("%s\t%s\t%s\t%s\t%s\n", ts, svc, ip.toString().c_str(), mac ? mac : "--", detail);
  f.close();
}

void logEvent(const char *svc, IPAddress ip, const String &detail,
              uint32_t colourHex, bool isAlert, bool loud) {
  st.total++;
  char ts[12];
  timeStr(ts, sizeof(ts), false);

  String mac = getMacForIp(ip);

  LogEntry entry;
  snprintf(entry.time, sizeof(entry.time), "%s", ts);
  snprintf(entry.svc, sizeof(entry.svc), "%s", svc);
  snprintf(entry.ip, sizeof(entry.ip), "%s", ip.toString().c_str());
  snprintf(entry.mac, sizeof(entry.mac), "%s", mac.c_str());
  snprintf(entry.detail, sizeof(entry.detail), "%s", detail.c_str());
  entry.color = colourHex;
  entry.isAlert = isAlert;

  if (logCount < MAX_UI_EVENTS) {
    logEntries[logCount++] = entry;
  } else {
    for (int i = 0; i < MAX_UI_EVENTS - 1; i++) logEntries[i] = logEntries[i + 1];
    logEntries[MAX_UI_EVENTS - 1] = entry;
  }

  Serial.printf("[%s] %-6s %-15s [%s] %s\n", ts, svc, ip.toString().c_str(), mac.c_str(), detail.c_str());
  fileLog(svc, ip, mac.c_str(), detail.c_str());

  addEventToUI(entry);
  updateDashboardMetrics();
  updateIpTableUI();

  stateDirty = true;
  if (loud) alertPulse();
}

void logCreds(const char *svc, IPAddress ip, const String &u, const String &p) {
  st.creds++;
  char ts[12];
  timeStr(ts, sizeof(ts), false);

  if (credCount < MAX_CAPTURED) {
    snprintf(credTab[credCount].time, sizeof(credTab[credCount].time), "%s", ts);
    snprintf(credTab[credCount].svc,  sizeof(credTab[credCount].svc), "%s", svc);
    snprintf(credTab[credCount].ip,   sizeof(credTab[credCount].ip), "%s", ip.toString().c_str());
    snprintf(credTab[credCount].user, sizeof(credTab[credCount].user), "%s", u.c_str());
    snprintf(credTab[credCount].pass, sizeof(credTab[credCount].pass), "%s", p.c_str());
    credCount++;
  } else {
    for (int i = 0; i < MAX_CAPTURED - 1; i++) credTab[i] = credTab[i + 1];
    snprintf(credTab[MAX_CAPTURED - 1].time, sizeof(credTab[MAX_CAPTURED - 1].time), "%s", ts);
    snprintf(credTab[MAX_CAPTURED - 1].svc,  sizeof(credTab[MAX_CAPTURED - 1].svc), "%s", svc);
    snprintf(credTab[MAX_CAPTURED - 1].ip,   sizeof(credTab[MAX_CAPTURED - 1].ip), "%s", ip.toString().c_str());
    snprintf(credTab[MAX_CAPTURED - 1].user, sizeof(credTab[MAX_CAPTURED - 1].user), "%s", u.c_str());
    snprintf(credTab[MAX_CAPTURED - 1].pass, sizeof(credTab[MAX_CAPTURED - 1].pass), "%s", p.c_str());
  }

  logEvent(svc, ip, "CREDS " + u + " / " + p, 0xF85149, true, true);
  updateLootUI();
  saveState(true);
}

void checkPayload(const char *svc, IPAddress ip, const String &cmd) {
  String l = cmd;
  l.toLowerCase();
  if (l.indexOf("wget") >= 0 || l.indexOf("curl") >= 0 ||
      l.indexOf("tftp") >= 0 || l.indexOf("http://") >= 0 ||
      l.indexOf("busybox") >= 0) {
    st.payloads++;
    char ts[12];
    timeStr(ts, sizeof(ts), false);

    if (payloadCount < MAX_CAPTURED) {
      snprintf(payloadTab[payloadCount].time, sizeof(payloadTab[payloadCount].time), "%s", ts);
      snprintf(payloadTab[payloadCount].svc,  sizeof(payloadTab[payloadCount].svc), "%s", svc);
      snprintf(payloadTab[payloadCount].ip,   sizeof(payloadTab[payloadCount].ip), "%s", ip.toString().c_str());
      snprintf(payloadTab[payloadCount].cmd,  sizeof(payloadTab[payloadCount].cmd), "%s", cmd.c_str());
      payloadCount++;
    } else {
      for (int i = 0; i < MAX_CAPTURED - 1; i++) payloadTab[i] = payloadTab[i + 1];
      snprintf(payloadTab[MAX_CAPTURED - 1].time, sizeof(payloadTab[MAX_CAPTURED - 1].time), "%s", ts);
      snprintf(payloadTab[MAX_CAPTURED - 1].svc,  sizeof(payloadTab[MAX_CAPTURED - 1].svc), "%s", svc);
      snprintf(payloadTab[MAX_CAPTURED - 1].ip,   sizeof(payloadTab[MAX_CAPTURED - 1].ip), "%s", ip.toString().c_str());
      snprintf(payloadTab[MAX_CAPTURED - 1].cmd,  sizeof(payloadTab[MAX_CAPTURED - 1].cmd), "%s", cmd.c_str());
    }

    logEvent(svc, ip, "PAYLOAD " + cmd, 0xF85149, true, true);
    updateLootUI();
    saveState(true);
  }
}


/*=================== 7. ICMP / PING DETECTION ==================*/
#if LWIP_RAW
static struct raw_pcb *icmpPcb = NULL;

static u8_t icmpRecv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
  (void)arg;
  (void)pcb;
  if (p != NULL && addr != NULL && p->len > 20) {
    const uint8_t *d = (const uint8_t *)p->payload;
    uint8_t ihl = (uint8_t)((d[0] & 0x0F) * 4);
    if (p->len > ihl && d[ihl] == 8) { // 8 = echo request
      uint32_t src = ip4_addr_get_u32(ip_2_ip4(addr));
      portENTER_CRITICAL_ISR(&icmpMux);
      uint8_t nxt = (uint8_t)((icmpHead + 1) % ICMP_Q);
      if (nxt != icmpTail) {
        icmpQ[icmpHead] = src;
        icmpHead = nxt;
      }
      portEXIT_CRITICAL_ISR(&icmpMux);
    }
  }
  return 0; // Return 0 to let lwIP answer normally
}

static void icmpInstall(void *arg) {
  (void)arg;
  icmpPcb = raw_new(IP_PROTO_ICMP);
  if (icmpPcb == NULL) return;
  raw_bind(icmpPcb, IP_ADDR_ANY);
  raw_recv(icmpPcb, icmpRecv, NULL);
}

void startIcmpWatch() {
  tcpip_callback(icmpInstall, NULL);
}
#else
void startIcmpWatch() {
  Serial.println("LWIP_RAW disabled");
}
#endif

void serviceIcmp() {
  while (true) {
    uint32_t src = 0;
    portENTER_CRITICAL(&icmpMux);
    if (icmpTail != icmpHead) {
      src = icmpQ[icmpTail];
      icmpTail = (uint8_t)((icmpTail + 1) % ICMP_Q);
    }
    portEXIT_CRITICAL(&icmpMux);
    if (src == 0) break;

    st.ping++;
    IPAddress ip(src);

    bool nu = false, sc = false;
    touchIp(ip, 16, nu, sc);

    bool quiet = false;
    for (uint8_t i = 0; i < ipCount; i++) {
      if (ipTab[i].ip == src) {
        if (ipTab[i].lastPing != 0 && (millis() - ipTab[i].lastPing) < PING_QUIET_MS) quiet = true;
        ipTab[i].lastPing = millis();
        break;
      }
    }

    if (!quiet) {
      logEvent("PING", ip, "icmp echo request", 0xDB61A2, false, false);
    } else {
      updateDashboardMetrics();
      stateDirty = true;
    }

    if (sc) logEvent("SCAN", ip, "multi-service probe", 0xBC8CFF, true, true);
  }
}


/*=================== 8. FAKE BUSYBOX SHELL =====================*/
String fakeShell(const String &cmd) {
  String c = cmd;
  c.trim();
  String l = c;
  l.toLowerCase();

  if (l == "") return "";
  if (l.startsWith("ls")) return "bin\ndev\netc\nlib\nmnt\nproc\nsbin\ntmp\nusr\nvar\n";
  if (l.startsWith("pwd")) return "/\n";
  if (l.startsWith("id") || l.startsWith("whoami")) return "uid=0(root) gid=0(root)\n";
  if (l.startsWith("uname")) return "Linux " + String(FAKE_HOST) + " 3.10.14 #1 SMP mips GNU/Linux\n";
  if (l.startsWith("cat /proc/cpuinfo"))
    return "system type\t: MT7620A\ncpu model\t: MIPS 24KEc V5.0\nBogoMIPS\t: 385.02\n";
  if (l.startsWith("cat /proc/mounts"))
    return "rootfs / rootfs rw 0 0\nproc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n";
  if (l.startsWith("free")) return "  total   used   free\nMem:  61120  42188  18932\n";
  if (l.startsWith("ps")) return "  PID USER  COMMAND\n    1 root  init\n  412 root  telnetd\n  530 root  httpd\n";
  if (l.startsWith("busybox")) return "BusyBox v1.20.2 (2016-11-28) multi-call binary.\n";
  if (l.startsWith("wget") || l.startsWith("curl") || l.startsWith("tftp"))
    return "sh: write error: Permission denied\n";
  if (l.startsWith("rm") || l.startsWith("chmod") || l.startsWith("mv")) return "";
  if (l.startsWith("echo ")) return c.substring(5) + "\n";
  if (l.startsWith("enable") || l.startsWith("system") || l.startsWith("shell") || l == "sh") return "";

  int sp = c.indexOf(' ');
  return "sh: " + c.substring(0, sp > 0 ? sp : c.length()) + ": applet not found\n";
}


/*=================== 9. TELNET =================================*/
bool readLine(Session &s) {
  while (s.c.available()) {
    int b = s.c.read();
    if (b < 0) break;
    s.last = millis();
    if (b == 0xFF) { // IAC skip
      if (s.c.available()) s.c.read();
      if (s.c.available()) s.c.read();
      continue;
    }
    if (b == '\n') return true;
    if (b == '\r' || b == 0) continue;
    if (s.line.length() < 96) s.line += (char)b;
  }
  return false;
}

void telnetPrompt() {
  tn.c.print("\r\n");
  tn.c.print(FAKE_HOST);
  tn.c.print(" login: ");
}

void handleTelnet() {
  if (!tn.active) {
    WiFiClient nc = srvAccept(srvTelnet);
    if (!nc) return;
    tn.c      = nc;
    tn.active = true;
    tn.stage  = 1;
    tn.tries  = 0;
    tn.line   = "";
    tn.user   = "";
    tn.last   = millis();
    tn.ip     = nc.remoteIP();
    st.telnet++;
    bool nu = false, sc = false;
    touchIp(tn.ip, 1, nu, sc);
    logEvent("TELNET", tn.ip, "connect", 0x3FB950, false);
    if (sc) logEvent("SCAN", tn.ip, "multi-service probe", 0xBC8CFF, true, true);
    telnetPrompt();
    return;
  }

  if (!tn.c.connected() || (millis() - tn.last) > 120000) {
    tn.c.stop();
    tn.active = false;
    return;
  }

  if (!readLine(tn)) return;
  String in = clean(tn.line);
  tn.line = "";

  if (tn.stage == 1) {
    tn.user = in.length() ? in : "(empty)";
    tn.c.print("\r\nPassword: ");
    tn.stage = 2;
  } else if (tn.stage == 2) {
    logCreds("TELNET", tn.ip, tn.user, in.length() ? in : "(empty)");
    tn.tries++;
    if (FAKE_SHELL && tn.tries >= 2) {
      tn.c.print("\r\n\r\nBusyBox v1.20.2 built-in shell (ash)\r\n\r\n# ");
      tn.stage = 3;
    } else if (tn.tries >= 3) {
      tn.c.print("\r\nLogin incorrect\r\n");
      tn.c.stop();
      tn.active = false;
    } else {
      tn.c.print("\r\nLogin incorrect\r\n");
      telnetPrompt();
      tn.stage = 1;
    }
  } else {
    if (in.length()) {
      logEvent("TELNET", tn.ip, "cmd: " + in, 0x3FB950, false);
      checkPayload("TELNET", tn.ip, in);
    }
    String low = in;
    low.toLowerCase();
    if (low == "exit" || low == "quit" || low == "logout") {
      tn.c.print("\r\n");
      tn.c.stop();
      tn.active = false;
      return;
    }
    tn.c.print("\r\n");
    tn.c.print(fakeShell(in));
    tn.c.print("# ");
  }
}


/*=================== 10. FTP ===================================*/
void handleFTP() {
  if (!ft.active) {
    WiFiClient nc = srvAccept(srvFTP);
    if (!nc) return;
    ft.c      = nc;
    ft.active = true;
    ft.stage  = 1;
    ft.tries  = 0;
    ft.line   = "";
    ft.user   = "";
    ft.last   = millis();
    ft.ip     = nc.remoteIP();
    st.ftp++;
    bool nu = false, sc = false;
    touchIp(ft.ip, 4, nu, sc);
    logEvent("FTP", ft.ip, "connect", 0xD29922, false);
    if (sc) logEvent("SCAN", ft.ip, "multi-service probe", 0xBC8CFF, true, true);
    ft.c.printf("220 %s FTP server (Version 6.4) ready.\r\n", FAKE_HOST);
    return;
  }

  if (!ft.c.connected() || (millis() - ft.last) > 90000) {
    ft.c.stop();
    ft.active = false;
    return;
  }
  if (!readLine(ft)) return;

  String in = clean(ft.line);
  ft.line = "";
  String up = in;
  up.toUpperCase();

  if (up.startsWith("USER")) {
    ft.user = in.length() > 5 ? in.substring(5) : "(empty)";
    ft.c.printf("331 Password required for %s.\r\n", ft.user.c_str());
  } else if (up.startsWith("PASS")) {
    String p = in.length() > 5 ? in.substring(5) : "(empty)";
    logCreds("FTP", ft.ip, ft.user, p);
    ft.tries++;
    ft.c.print("530 Login incorrect.\r\n");
    if (ft.tries >= 3) { ft.c.stop(); ft.active = false; }
  } else if (up.startsWith("QUIT")) {
    ft.c.print("221 Goodbye.\r\n");
    ft.c.stop();
    ft.active = false;
  } else if (up.startsWith("SYST")) {
    ft.c.print("215 UNIX Type: L8\r\n");
  } else if (in.length()) {
    logEvent("FTP", ft.ip, "cmd: " + in, 0xD29922, false);
    ft.c.print("530 Please login with USER and PASS.\r\n");
  }
}


/*=================== 11. SSH ===================================*/
void handleSSH() {
  WiFiClient c = srvAccept(srvSSH);
  if (!c) return;
  IPAddress ip = c.remoteIP();
  st.ssh++;
  bool nu = false, sc = false;
  touchIp(ip, 2, nu, sc);
  logEvent("SSH", ip, "connect", 0x39C5CF, false);
  if (sc) logEvent("SCAN", ip, "multi-service probe", 0xBC8CFF, true, true);

  c.print("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n");

  String ident;
  uint32_t t0 = millis();
  bool done = false;
  while ((millis() - t0) < 1200 && c.connected() && ident.length() < 80 && !done) {
    while (c.available()) {
      int b = c.read();
      if (b == '\n') { done = true; break; }
      if (b >= 32 && b <= 126) ident += (char)b;
    }
    if (!done) delay(10);
  }
  if (ident.length()) logEvent("SSH", ip, "client: " + clean(ident), 0x39C5CF, false);
  c.stop();
}


/*=================== 12. HTTP DECOY ============================*/
const char LOGIN_PAGE[] PROGMEM = R"HTML(<!DOCTYPE html><html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>SynologyNAS — Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;width:100%;overflow:hidden}
body{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#0e86ea 0%,#0064c8 45%,#015cb8 75%,#004b96 100%);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  color:#fff;position:relative;user-select:none;
}
body::before{
  content:'';position:absolute;top:-25%;right:-25%;width:110vw;height:150vh;
  border-radius:50%;
  background:radial-gradient(ellipse at center,rgba(255,255,255,0.22) 0%,rgba(255,255,255,0.04) 45%,transparent 70%);
  pointer-events:none;transform:rotate(-15deg);
}
body::after{
  content:'';position:absolute;bottom:-35%;right:-15%;width:120vw;height:140vh;
  border-radius:50%;
  border:1px solid rgba(255,255,255,0.12);
  background:radial-gradient(ellipse at center,rgba(255,255,255,0.12) 0%,transparent 65%);
  pointer-events:none;
}
.login-wrap{position:relative;z-index:2;display:flex;flex-direction:column;align-items:center}
.nas-title{
  font-size:24px;font-weight:400;color:#ffffff;letter-spacing:0.4px;
  margin-bottom:22px;text-shadow:0 1px 4px rgba(0,0,0,0.25);
}
.login-box{
  width:304px;background:rgba(255,255,255,0.22);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid rgba(255,255,255,0.32);border-radius:4px;
  box-shadow:0 8px 30px rgba(0,0,0,0.18),0 1px 3px rgba(0,0,0,0.1);
  padding:0 0 16px 0;overflow:hidden;
}
.field-row{
  display:flex;align-items:center;padding:0 14px;height:44px;
  border-bottom:1px solid rgba(255,255,255,0.25);background:rgba(255,255,255,0.06);
}
.field-row:focus-within{background:rgba(255,255,255,0.12)}
.field-icon{width:22px;display:flex;align-items:center;justify-content:center;margin-right:10px;opacity:0.95}
.field-row input{
  flex:1;background:transparent;border:none;outline:none;
  color:#ffffff;font-size:14px;font-family:inherit;
}
.field-row input::placeholder{color:rgba(255,255,255,0.72);font-weight:300}
.chk-row{
  display:flex;align-items:center;padding:12px 16px 14px 16px;font-size:12.5px;color:#ffffff;
  user-select:none;cursor:pointer;
}
.chk-row input[type=checkbox]{
  width:15px;height:15px;margin-right:8px;accent-color:#0076f6;cursor:pointer;
}
.btn-submit{
  display:block;width:calc(100% - 32px);margin:0 16px;height:36px;
  background:linear-gradient(to bottom,#0084f8,#006de0);
  border:1px solid #005bbd;border-radius:3px;color:#ffffff;
  font-size:13.5px;font-weight:500;font-family:inherit;cursor:pointer;
  box-shadow:0 1px 4px rgba(0,0,0,0.2);transition:background 0.15s,box-shadow 0.15s;
}
.btn-submit:hover{background:linear-gradient(to bottom,#1a90f9,#0076ea)}
.btn-submit:active{background:#0062cc}
.err-box{
  margin:10px 16px 0;padding:6px 10px;background:rgba(220,38,38,0.35);
  border:1px solid rgba(248,113,113,0.5);border-radius:3px;color:#fff;
  font-size:11.5px;text-align:center;
}
.footer-brand{
  position:absolute;bottom:22px;right:28px;color:rgba(255,255,255,0.45);
  font-size:12px;font-weight:400;letter-spacing:0.2px;z-index:2;display:flex;align-items:center;
}
.footer-brand b{font-weight:600;color:rgba(255,255,255,0.6);margin-right:4px}
.footer-brand span.beta{
  font-size:9px;font-weight:700;letter-spacing:0.8px;
  border:1px solid rgba(255,255,255,0.35);border-radius:2px;
  padding:0 3px;margin-left:5px;line-height:1.2;
}
</style></head><body>
<div class=login-wrap>
  <div class=nas-title>SynologyNAS</div>
  <form class=login-box method=POST action=/login>
    <div class=field-row>
      <div class=field-icon>
        <svg width=17 height=17 viewBox="0 0 24 24" fill=#ffffff><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
      </div>
      <input name=username type=text placeholder=Username autocomplete=username>
    </div>
    <div class=field-row>
      <div class=field-icon>
        <svg width=17 height=17 viewBox="0 0 24 24" fill=#ffffff><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
      </div>
      <input name=password type=password placeholder=Password autocomplete=current-password>
    </div>
    <div class=chk-row onclick="var c=document.getElementById('chkStay');c.checked=!c.checked;">
      <input id=chkStay type=checkbox checked onclick="event.stopPropagation()">
      <span>Stay signed in</span>
    </div>
    %MSG%
    <button class=btn-submit type=submit>Sign in</button>
  </form>
</div>
<div class=footer-brand>
  <b>Synology</b> DSM 6.1 <span class=beta>BETA</span>
</div>
</body></html>)HTML";

String urlDecode(String s) {
  String o;
  char a, b;
  for (uint16_t i = 0; i < s.length(); i++) {
    if (s[i] == '%' && (uint32_t)(i + 2) < s.length()) {
      a = s[i + 1];
      b = s[i + 2];
      a = (a <= '9') ? a - '0' : (a & 0xDF) - 'A' + 10;
      b = (b <= '9') ? b - '0' : (b & 0xDF) - 'A' + 10;
      o += (char)(a * 16 + b);
      i += 2;
    } else if (s[i] == '+') {
      o += ' ';
    } else {
      o += s[i];
    }
  }
  return o;
}

String formField(const String &body, const String &key) {
  int i = body.indexOf(key + "=");
  if (i < 0) return "";
  i += key.length() + 1;
  int e = body.indexOf('&', i);
  int sp = body.indexOf(' ', i);
  if (e < 0 || (sp >= 0 && sp < e)) e = sp;
  int cr = body.indexOf('\r', i);
  if (e < 0 || (cr >= 0 && cr < e)) e = cr;
  int nl = body.indexOf('\n', i);
  if (e < 0 || (nl >= 0 && nl < e)) e = nl;
  if (e < 0) e = body.length();
  return urlDecode(body.substring(i, e));
}

void handleHTTP() {
  WiFiClient c = srvAccept(srvHTTP);
  if (!c) return;
  IPAddress ip = c.remoteIP();
  st.http++;
  bool nu = false, sc = false;
  touchIp(ip, 8, nu, sc);

  String headers;
  uint32_t t0 = millis();
  while ((millis() - t0) < 2000 && c.connected()) {
    if (c.available()) {
      char ch = c.read();
      headers += ch;
      if (headers.length() > 2000) break;
      if (headers.endsWith("\r\n\r\n")) break;
    } else {
      delay(2);
    }
  }
  int nl = headers.indexOf("\r\n");
  String req = (nl > 0) ? headers.substring(0, nl) : headers;

  String body;
  int cl = 0;
  int p = headers.indexOf("Content-Length:");
  if (p < 0) p = headers.indexOf("content-length:");
  if (p >= 0) cl = headers.substring(p + 15, headers.indexOf("\r\n", p)).toInt();
  if (cl > 0 && cl < 1024) {
    t0 = millis();
    while ((int)body.length() < cl && (millis() - t0) < 1500 && c.connected()) {
      while (c.available() && (int)body.length() < cl) body += (char)c.read();
      delay(2);
    }
  }

  String ua;
  p = headers.indexOf("User-Agent:");
  if (p < 0) p = headers.indexOf("user-agent:");
  if (p >= 0) ua = clean(headers.substring(p + 11, headers.indexOf("\r\n", p)), 40);

  String path = "/", method = "GET";
  int s1 = req.indexOf(' ');
  int s2 = req.indexOf(' ', s1 + 1);
  if (s1 > 0) {
    method = req.substring(0, s1);
    if (s2 > s1) path = req.substring(s1 + 1, s2);
  }

  logEvent("HTTP", ip, method + " " + clean(path, 30), 0xF0883E, false);
  if (sc) logEvent("SCAN", ip, "multi-service probe", 0xBC8CFF, true, true);
  if (ua.length()) logEvent("HTTP", ip, "UA " + ua, 0x8B949E, false);

  if (path != "/" && path != "/favicon.ico" && path != "/login")
    logEvent("HTTP", ip, "PROBE " + clean(path, 34), 0xF85149, true, true);

  String msg;
  if (method == "POST" && body.length()) {
    String u = clean(formField(body, "username"));
    String w = clean(formField(body, "password"));
    if (u.length() || w.length()) {
      logCreds("HTTP", ip, u.length() ? u : "(empty)", w.length() ? w : "(empty)");
    } else {
      logEvent("HTTP", ip, "POST " + clean(body, 34), 0xF85149, true, true);
    }
    msg = "<div class='err-box'>The username or password is invalid.</div>";
  }

  String page = FPSTR(LOGIN_PAGE);
  page.replace("%MSG%", msg);
  c.print("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\n"
          "Content-Type: text/html\r\nConnection: close\r\nContent-Length: ");
  c.print(page.length());
  c.print("\r\n\r\n");
  c.print(page);
  delay(5);
  c.stop();
}


/*=================== 13. WEB DASHBOARD :8080 ==================*/

/* ── Login page (Synology DSM 6.1 Authenticator Gateway) ─────── */
static const char LOGIN_HTML[] PROGMEM = R"HTML(<!DOCTYPE html><html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>SynologyNAS — Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;width:100%;overflow:hidden}
body{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#0e86ea 0%,#0064c8 45%,#015cb8 75%,#004b96 100%);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  color:#fff;position:relative;user-select:none;
}
body::before{
  content:'';position:absolute;top:-25%;right:-25%;width:110vw;height:150vh;
  border-radius:50%;
  background:radial-gradient(ellipse at center,rgba(255,255,255,0.22) 0%,rgba(255,255,255,0.04) 45%,transparent 70%);
  pointer-events:none;transform:rotate(-15deg);
}
body::after{
  content:'';position:absolute;bottom:-35%;right:-15%;width:120vw;height:140vh;
  border-radius:50%;
  border:1px solid rgba(255,255,255,0.12);
  background:radial-gradient(ellipse at center,rgba(255,255,255,0.12) 0%,transparent 65%);
  pointer-events:none;
}
.login-wrap{position:relative;z-index:2;display:flex;flex-direction:column;align-items:center}
.nas-title{
  font-size:24px;font-weight:400;color:#ffffff;letter-spacing:0.4px;
  margin-bottom:22px;text-shadow:0 1px 4px rgba(0,0,0,0.25);
}
.login-box{
  width:304px;background:rgba(255,255,255,0.22);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid rgba(255,255,255,0.32);border-radius:4px;
  box-shadow:0 8px 30px rgba(0,0,0,0.18),0 1px 3px rgba(0,0,0,0.1);
  padding:0 0 16px 0;overflow:hidden;
}
.field-row{
  display:flex;align-items:center;padding:0 14px;height:44px;
  border-bottom:1px solid rgba(255,255,255,0.25);background:rgba(255,255,255,0.06);
}
.field-row:focus-within{background:rgba(255,255,255,0.12)}
.field-icon{width:22px;display:flex;align-items:center;justify-content:center;margin-right:10px;opacity:0.95}
.field-row input{
  flex:1;background:transparent;border:none;outline:none;
  color:#ffffff;font-size:14px;font-family:inherit;
}
.field-row input::placeholder{color:rgba(255,255,255,0.72);font-weight:300}
.chk-row{
  display:flex;align-items:center;padding:12px 16px 14px 16px;font-size:12.5px;color:#ffffff;
  user-select:none;cursor:pointer;
}
.chk-row input[type=checkbox]{
  width:15px;height:15px;margin-right:8px;accent-color:#0076f6;cursor:pointer;
}
.btn-submit{
  display:block;width:calc(100% - 32px);margin:0 16px;height:36px;
  background:linear-gradient(to bottom,#0084f8,#006de0);
  border:1px solid #005bbd;border-radius:3px;color:#ffffff;
  font-size:13.5px;font-weight:500;font-family:inherit;cursor:pointer;
  box-shadow:0 1px 4px rgba(0,0,0,0.2);transition:background 0.15s,box-shadow 0.15s;
}
.btn-submit:hover{background:linear-gradient(to bottom,#1a90f9,#0076ea)}
.btn-submit:active{background:#0062cc}
.err-box{
  margin:10px 16px 0;padding:6px 10px;background:rgba(220,38,38,0.35);
  border:1px solid rgba(248,113,113,0.5);border-radius:3px;color:#fff;
  font-size:11.5px;text-align:center;display:none;
}
.footer-brand{
  position:absolute;bottom:22px;right:28px;color:rgba(255,255,255,0.45);
  font-size:12px;font-weight:400;letter-spacing:0.2px;z-index:2;display:flex;align-items:center;
}
.footer-brand b{font-weight:600;color:rgba(255,255,255,0.6);margin-right:4px}
.footer-brand span.beta{
  font-size:9px;font-weight:700;letter-spacing:0.8px;
  border:1px solid rgba(255,255,255,0.35);border-radius:2px;
  padding:0 3px;margin-left:5px;line-height:1.2;
}
</style></head><body>
<div class=login-wrap>
  <div class=nas-title>SynologyNAS</div>
  <div class=login-box>
    <div class=field-row>
      <div class=field-icon>
        <svg width=17 height=17 viewBox="0 0 24 24" fill=#ffffff><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
      </div>
      <input id=u type=text placeholder=Username autocomplete=username value=admin>
    </div>
    <div class=field-row>
      <div class=field-icon>
        <svg width=17 height=17 viewBox="0 0 24 24" fill=#ffffff><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
      </div>
      <input id=p type=password placeholder=Password autocomplete=current-password>
    </div>
    <div class=chk-row onclick="var c=document.getElementById('chkStay');c.checked=!c.checked;">
      <input id=chkStay type=checkbox checked onclick="event.stopPropagation()">
      <span>Stay signed in</span>
    </div>
    <div class=err-box id=err>The username or password is invalid.</div>
    <button class=btn-submit type=button onclick=tryLogin()>Sign in</button>
  </div>
</div>
<div class=footer-brand>
  <b>Synology</b> DSM 6.1 <span class=beta>BETA</span>
</div>
<script>
document.getElementById('p').addEventListener('keydown',function(e){if(e.key==='Enter')tryLogin();});
document.getElementById('u').addEventListener('keydown',function(e){if(e.key==='Enter')tryLogin();});
function tryLogin(){
  var k=document.getElementById('p').value.trim();
  var u=document.getElementById('u').value.trim();
  if(!k && u) k = u;
  if(!k){document.getElementById('err').style.display='block';return;}
  fetch('/api?key='+encodeURIComponent(k))
    .then(function(r){
      if(r.ok&&r.status===200){
        try{ sessionStorage.setItem('vera_key',k); }catch(e){}
        window.location='/ui?key='+encodeURIComponent(k);
      } else {
        document.getElementById('err').style.display='block';
      }
    })
    .catch(function(){document.getElementById('err').style.display='block';});
}
</script></body></html>)HTML";

/* ── Full mirrored dashboard ─────────────────────────────────── */
static const char DASH_HTML[] PROGMEM = R"HTML(<!DOCTYPE html><html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>VERA — Dashboard</title>
<style>
:root{--bg:#090e14;--card:#0f1720;--card2:#141b23;--line:#1a2535;--txt:#c9d6e2;--dim:#4d6478;
--telnet:#3fb950;--ssh:#39c5cf;--ftp:#d29922;--http:#f0883e;--ping:#db61a2;
--cred:#f85149;--scan:#bc8cff;--sys:#6b7d8f;--blue:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);
  font:13px/1.5 'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column}
/* ── Header ── */
header{background:#0b1520;border-bottom:1px solid var(--line);
  padding:0 18px;height:52px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:99}
.logo{font-size:18px;font-weight:800;letter-spacing:3px;color:#58d9f9;
  text-shadow:0 0 14px rgba(88,217,249,.3);margin-right:4px}
.logo-sub{font-size:9.5px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;line-height:1}
.pill{background:var(--card);border:1px solid var(--line);padding:3px 10px;
  border-radius:99px;font-size:11px;color:var(--dim);white-space:nowrap}
.pill.ok{color:var(--telnet);border-color:#1c3a24}
.pill.bad{color:var(--cred);border-color:#4a1d1d}
.pill.warn{color:#d29922;border-color:#4a3800}
.pill.chg{color:#3fb950;border-color:#1c3a24}
.pill.low{color:#f85149;border-color:#4a1d1d}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:6px}
/* ── Tab nav ── */
nav{background:#0b1520;border-bottom:1px solid var(--line);
  display:flex;padding:0 18px;gap:2px}
.tab{padding:10px 16px;font-size:12px;font-weight:500;cursor:pointer;color:var(--dim);
  border-bottom:2px solid transparent;transition:color .15s,border-color .15s;letter-spacing:.3px}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab:hover:not(.active){color:var(--txt)}
/* ── Content ── */
main{flex:1;padding:16px 18px;max-width:1400px;width:100%;margin:auto}
/* ── Metric grid ── */
.grid{display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));margin-bottom:10px}
.card{background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:10px 13px;
  position:relative;overflow:hidden}
.card::before{content:'';position:absolute;inset:0;opacity:.04;border-radius:10px}
.card.telnet{border-left:3px solid var(--telnet)}.card.telnet::before{background:var(--telnet)}
.card.ssh{border-left:3px solid var(--ssh)}.card.ssh::before{background:var(--ssh)}
.card.ftp{border-left:3px solid var(--ftp)}.card.ftp::before{background:var(--ftp)}
.card.http{border-left:3px solid var(--http)}.card.http::before{background:var(--http)}
.card.ping{border-left:3px solid var(--ping)}.card.ping::before{background:var(--ping)}
.card.cred{border-left:3px solid var(--cred)}.card.cred::before{background:var(--cred)}
.card.scan{border-left:3px solid var(--scan)}.card.scan::before{background:var(--scan)}
.card .lbl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:3px}
.card .val{font-size:26px;font-weight:700;line-height:1}
/* ── Two-column layout ── */
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
@media(max-width:700px){.row2{grid-template-columns:1fr}}
.panel{background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:13px 15px}
.panel-title{font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;
  margin-bottom:10px;font-weight:600}
/* ── Distribution bars ── */
.bar{display:flex;align-items:center;gap:8px;margin:6px 0}
.bar .bl{width:56px;font-size:11px;font-weight:600;color:var(--dim)}
.bar .bt{flex:1;background:#0b1520;border-radius:4px;height:14px;border:1px solid var(--line);overflow:hidden}
.bar .bf{display:block;height:100%;border-radius:3px;transition:width .4s ease;min-width:0}
.bar .bn{width:40px;text-align:right;font-size:11px;font-weight:700}
/* ── Ticker ── */
.ticker{font-size:11px;line-height:2;font-family:ui-monospace,Menlo,monospace}
.ticker div{padding:2px 0;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ticker div:last-child{border-bottom:none}
/* ── Table ── */
.wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;max-height:420px}
table{width:100%;border-collapse:collapse;font-size:12px}
thead{position:sticky;top:0}
th{text-align:left;color:var(--dim);font-weight:500;padding:7px 10px;
  border-bottom:1px solid var(--line);background:#0b1520;font-size:11px;letter-spacing:.3px}
td{padding:5px 10px;border-bottom:1px solid #111d29;vertical-align:top}
td.det{word-break:break-all;color:#e6edf3}
tr.hot td{background:#1a0f10}
.badge{padding:1px 7px;border-radius:4px;font-size:10px;font-weight:700;color:#060c12}
.empty{padding:24px;text-align:center;color:var(--dim);font-size:12px}
/* ── Tools bar ── */
.tools{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px;align-items:center}
.btn{background:var(--card2);color:var(--txt);border:1px solid var(--line);
  padding:5px 12px;border-radius:7px;cursor:pointer;font:inherit;font-size:11.5px;transition:border-color .15s}
.btn.on{border-color:var(--blue);color:var(--blue)}
.btn:hover{border-color:var(--blue)}
.inp{background:var(--card2);border:1px solid var(--line);color:var(--txt);
  padding:5px 11px;border-radius:7px;font:inherit;font-size:11.5px;flex:1;min-width:130px;outline:none}
.inp:focus{border-color:var(--blue)}
/* ── Battery card ── */
.bat-bar-wrap{background:#0b1520;border:1px solid var(--line);border-radius:6px;
  height:22px;overflow:hidden;margin:10px 0 6px}
.bat-bar-fill{height:100%;border-radius:5px;transition:width .5s,background .5s;min-width:2px}
.bat-row{display:flex;justify-content:space-between;font-size:12px;margin:3px 0}
.bat-k{color:var(--dim)}.bat-v{font-weight:600}
/* ── Section title ── */
.sec{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;
  color:var(--dim);margin:14px 0 8px}
/* ── Sys info ── */
.sinfo{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.srow{background:#0b1520;border:1px solid var(--line);border-radius:7px;padding:8px 11px}
.srow .sk{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.srow .sv{font-size:14px;font-weight:600;margin-top:2px}
footer{padding:10px 18px;color:var(--dim);font-size:11px;border-top:1px solid var(--line);
  display:flex;gap:14px;flex-wrap:wrap}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.page{display:none}.page.active{display:block}
</style></head><body>
<header>
  <div><div class=logo>VERA</div><div class=logo-sub>Cyber Defense Node</div></div>
  <span class=pill id=pSd>storage</span>
  <span class=pill id=pBat>battery</span>
  <div class=hdr-right>
    <span class=pill id=pIp>ip</span>
    <span class=pill id=pUp>uptime</span>
    <span class=pill id=pRssi>rssi</span>
    <span class=pill id=pHeap>heap</span>
    <span class=pill id=pSeen style=color:#3fb950>●</span>
  </div>
</header>
<nav>
  <div class="tab active" onclick=showTab(0)>Overview</div>
  <div class=tab onclick=showTab(1)>Threat Log</div>
  <div class=tab onclick=showTab(2)>Attackers</div>
  <div class=tab onclick=showTab(3)>Captured Loot</div>
  <div class=tab onclick=showTab(4)>System</div>
</nav>
<main>
<!-- TAB 0: OVERVIEW -->
<div class="page active" id=t0>
  <div class=grid>
    <div class="card telnet"><div class=lbl>Telnet (23)</div><div class=val id=cTelnet>0</div></div>
    <div class="card ssh"><div class=lbl>SSH (22)</div><div class=val id=cSsh>0</div></div>
    <div class="card ftp"><div class=lbl>FTP (21)</div><div class=val id=cFtp>0</div></div>
    <div class="card http"><div class=lbl>HTTP (80)</div><div class=val id=cHttp>0</div></div>
    <div class="card ping"><div class=lbl>Ping (ICMP)</div><div class=val id=cPing>0</div></div>
  </div>
  <div class=grid>
    <div class=card><div class=lbl>Total Probes</div><div class=val id=cTotal>0</div></div>
    <div class=card><div class=lbl>Unique Hosts</div><div class=val id=cIps>0</div></div>
    <div class="card cred"><div class=lbl>Creds Harvest</div><div class=val id=cCreds>0</div></div>
    <div class="card cred"><div class=lbl>Shell Payloads</div><div class=val id=cPayl>0</div></div>
    <div class="card scan"><div class=lbl>Port Scanners</div><div class=val id=cScans>0</div></div>
  </div>
  <div class=row2>
    <div class=panel>
      <div class=panel-title>Service Attack Distribution</div>
      <div id=bars></div>
    </div>
    <div class=panel>
      <div class=panel-title>Latest Threat Feed</div>
      <div class=ticker id=ticker><div style=color:var(--dim)>[--:--:--] System Armed. Awaiting inbound probes...</div></div>
    </div>
  </div>
</div>
<!-- TAB 1: THREAT LOG -->
<div class=page id=t1>
  <div class=tools>
    <button class="btn on" data-f=ALL>All</button>
    <button class=btn data-f=TELNET>Telnet</button>
    <button class=btn data-f=SSH>SSH</button>
    <button class=btn data-f=FTP>FTP</button>
    <button class=btn data-f=HTTP>HTTP</button>
    <button class=btn data-f=PING>Ping</button>
    <button class=btn data-f=HOT>Alerts Only</button>
    <input class=inp id=q placeholder="Filter by IP, service, or keyword…">
    <button class=btn id=pauseBtn>Pause</button>
  </div>
  <div class=wrap><table><thead><tr>
    <th style=width:78px>Time</th><th style=width:72px>Service</th>
    <th style=width:165px>Source IP &amp; MAC</th><th>Detail</th>
  </tr></thead><tbody id=evBody></tbody></table></div>
</div>
<!-- TAB 2: ATTACKERS -->
<div class=page id=t2>
  <div class=wrap style=max-height:none><table><thead><tr>
    <th>Source IP</th><th>MAC Address</th><th>Services Touched</th><th>Threat Level</th>
  </tr></thead><tbody id=ipBody></tbody></table></div>
</div>
<!-- TAB 3: LOOT -->
<div class=page id=t3>
  <div class=sec>Captured Credentials</div>
  <div class=wrap><table><thead><tr>
    <th>Time</th><th>Service</th><th>Source IP</th><th>Username</th><th>Password</th>
  </tr></thead><tbody id=credBody></tbody></table></div>
  <div class=sec>Shell Payloads</div>
  <div class=wrap><table><thead><tr>
    <th>Time</th><th>Service</th><th>Source IP</th><th>Command</th>
  </tr></thead><tbody id=paylBody></tbody></table></div>
</div>
<!-- TAB 4: SYSTEM -->
<div class=page id=t4>
  <div class=row2>
    <div class=panel>
      <div class=panel-title>Power &amp; Battery Subsystem</div>
      <div class=bat-bar-wrap><div class=bat-bar-fill id=batFill style=width:0%></div></div>
      <div class=bat-row><span class=bat-k>Voltage</span><span class=bat-v id=batV>-- V</span></div>
      <div class=bat-row><span class=bat-k>Charge Level</span><span class=bat-v id=batPct>--%</span></div>
      <div class=bat-row><span class=bat-k>Status</span><span class=bat-v id=batStat>Reading...</span></div>
      <div style=margin-top:10px;font-size:10.5px;color:var(--dim);line-height:1.7>
        MANAGEMENT IC: CS8501 580mA Charge / 5V Boost<br>
        BATTERY SOCKET: PH2.0 (Single-Cell 3.7V Li-ion)<br>
        MONITOR ADC: CH32V003 Register 0x06 (3:1 Divider)
      </div>
    </div>
    <div class=panel>
      <div class=panel-title>System &amp; Network</div>
      <div class=sinfo>
        <div class=srow><div class=sk>IP Address</div><div class=sv id=sIp>--</div></div>
        <div class=srow><div class=sk>Signal (RSSI)</div><div class=sv id=sRssi>-- dBm</div></div>
        <div class=srow><div class=sk>Free Heap</div><div class=sv id=sHeap>-- kB</div></div>
        <div class=srow><div class=sk>Uptime</div><div class=sv id=sUp>--</div></div>
        <div class=srow><div class=sk>Boot Count</div><div class=sv id=sBoots>--</div></div>
        <div class=srow><div class=sk>MicroSD</div><div class=sv id=sSd>--</div></div>
      </div>
    </div>
  </div>
  <div class=panel style="margin-top:10px">
    <div class=panel-title>Wi-Fi Network Configuration &amp; Connect</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
      <button class=btn id=btnScanWifi onclick=scanWifi()>🔍 Scan Networks</button>
      <select id=selWifi onchange="pickWifi(this.value)" class=inp style="max-width:240px">
        <option value="">-- Scanned APs --</option>
      </select>
      <input id=wSsid class=inp placeholder="SSID (Network Name)" style="max-width:220px">
      <input id=wPass class=inp type=password placeholder="Password" style="max-width:200px">
      <button class=btn style="background:#238636;border-color:#2ea043;color:#fff;font-weight:600" onclick=connectWifi()>Connect Wi-Fi</button>
    </div>
    <div id=wMsg style="font-size:12px;color:var(--dim)">Current Wi-Fi: <b id=wCurSsid>--</b> &middot; Status: <span id=wCurStat style="color:#3fb950">Online</span></div>
  </div>
</div>
</main>
<footer>
  VERA v2.0 &nbsp;&middot;&nbsp;
  <a id=lnkRaw href=#>Download full log</a> &nbsp;&middot;&nbsp;
  <a id=lnkClear href=# style=color:var(--cred)>Clear all data</a>
</footer>
<script>
var KEY=new URLSearchParams(location.search).get('key')||'';
try{if(!KEY)KEY=sessionStorage.getItem('vera_key')||'';else sessionStorage.setItem('vera_key',KEY);}catch(e){}
var COL={TELNET:'--telnet',SSH:'--ssh',FTP:'--ftp',HTTP:'--http',PING:'--ping',SCAN:'--scan',SYS:'--sys'};
var filter='ALL',live=true,rows=[],curTab=0;
document.getElementById('lnkRaw').href='/raw?key='+encodeURIComponent(KEY);
document.getElementById('lnkClear').onclick=function(e){e.preventDefault();
  if(confirm('Erase the whole log and all counters?'))
    fetch('/clear?key='+encodeURIComponent(KEY)).then(function(){location.reload();});};
// Tab switching
function showTab(n){
  document.querySelectorAll('.page').forEach(function(p,i){p.classList.toggle('active',i===n);});
  document.querySelectorAll('.tab').forEach(function(t,i){t.classList.toggle('active',i===n);});
  curTab=n;
}
// Wi-Fi Management
function scanWifi(){
  var b=document.getElementById('btnScanWifi');
  if(b){b.disabled=true;b.textContent='Scanning...';}
  var s=document.getElementById('selWifi');
  s.innerHTML='<option>Scanning 2.4GHz networks...</option>';
  fetch('/wifi/scan?key='+encodeURIComponent(KEY)).then(function(r){
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  })
  .then(function(d){
    if(b){b.disabled=false;b.textContent='🔍 Scan Networks';}
    if(!d.nets || !d.nets.length){
      s.innerHTML='<option value="">-- No APs found --</option>';
      return;
    }
    s.innerHTML='<option value="">-- Select AP ('+d.nets.length+' found) --</option>';
    d.nets.forEach(function(n){
      var o=document.createElement('option');
      o.value=n.ssid;
      o.textContent=n.ssid+' ('+n.rssi+' dBm)';
      s.appendChild(o);
    });
  }).catch(function(e){
    if(b){b.disabled=false;b.textContent='🔍 Scan Networks';}
    s.innerHTML='<option>Scan failed ('+(e.message||'error')+'). Tap to retry.</option>';
  });
}
function pickWifi(v){
  if(v){
    document.getElementById('wSsid').value=v;
    var p=document.getElementById('wPass');
    p.value='';
    p.focus();
  }
}
function connectWifi(){
  var s=document.getElementById('wSsid').value.trim();
  var p=document.getElementById('wPass').value;
  if(!s){alert('Please enter or select an SSID');return;}
  var m=document.getElementById('wMsg');
  m.innerHTML='<span style="color:#d29922">Connecting to <b>'+esc(s)+'</b>... (device will switch networks)</span>';
  fetch('/wifi/connect?key='+encodeURIComponent(KEY)+'&ssid='+encodeURIComponent(s)+'&pass='+encodeURIComponent(p))
    .then(function(r){
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(d){
      m.innerHTML='<span style="color:#3fb950">'+esc(d.msg)+'</span>';
    }).catch(function(){
      m.innerHTML='<span style="color:#58a6ff">Reconnection in progress. Check device screen for new IP address.</span>';
    });
}
var wp=document.getElementById('wPass');
if(wp) wp.addEventListener('keydown',function(e){if(e.key==='Enter')connectWifi();});

// Filter buttons
document.querySelectorAll('button[data-f]').forEach(function(b){
  b.onclick=function(){filter=b.dataset.f;
    document.querySelectorAll('button[data-f]').forEach(function(x){x.classList.toggle('on',x===b)});draw();};});
document.getElementById('q').oninput=draw;
document.getElementById('pauseBtn').onclick=function(){live=!live;this.textContent=live?'Pause':'Resume';this.classList.toggle('on',!live);};
function esc(t){return (t||'').replace(/[<>&]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c]});}
function hot(sv,d){return sv==='SCAN'||/^(CREDS|PAYLOAD|PROBE)/.test(d);}
function svcName(m){var o=[];if(m&1)o.push('Telnet');if(m&2)o.push('SSH');if(m&4)o.push('FTP');if(m&8)o.push('HTTP');if(m&16)o.push('Ping');return o.join(', ')||'—';}
function draw(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var out=rows.filter(function(r){
    if(filter==='HOT'&&!hot(r[1],r[3]))return false;
    if(filter!=='ALL'&&filter!=='HOT'&&r[1]!==filter)return false;
    if(q&&(r.join(' ').toLowerCase().indexOf(q)<0))return false;
    return true;}).slice(-400).reverse();
  var b=document.getElementById('evBody');
  if(!b)return;
  if(!out.length){b.innerHTML='<tr><td colspan=4 class=empty>No matching events</td></tr>';return;}
  b.innerHTML=out.map(function(r){
    var c=COL[r[1]]||'--sys';
    var isHot=hot(r[1],r[3]);
    var macInfo=(r[5]&&r[5]!=='--')?'<div style="font-size:11px;color:#8b949e;font-family:monospace">'+esc(r[5])+'</div>':'';
    return '<tr class="'+(isHot?'hot':'')+'"><td>'+esc(r[0])+
    '</td><td><span class=badge style="background:var('+c+');color:#060c12">'+esc(r[1])+
    '</span></td><td><b>'+esc(r[2])+'</b>'+macInfo+'</td><td class=det>'+esc(r[3])+'</td></tr>';
  }).join('');}
function bars(d){
  var S=[['TELNET',d.telnet||0,'--telnet'],['SSH',d.ssh||0,'--ssh'],['FTP',d.ftp||0,'--ftp'],['HTTP',d.http||0,'--http'],['PING',d.ping||0,'--ping']];
  var mx=Math.max(1,d.telnet||0,d.ssh||0,d.ftp||0,d.http||0,d.ping||0);
  var el=document.getElementById('bars');
  if(!el)return;
  el.innerHTML=S.map(function(x){
    var pct=(x[1]>0)?Math.max(4,Math.round(x[1]/mx*100)):0;
    return '<div class=bar><span class=bl>'+x[0]+'</span><span class=bt>'+
    '<span class=bf style="display:block;height:100%;width:'+pct+'%;background:var('+x[2]+')"></span>'+
    '</span><span class=bn>'+x[1]+'</span></div>';}).join('');}
function fmtUp(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m';}
function updateTicker(evs){
  var t=document.getElementById('ticker');
  if(!t)return;
  var last=evs.slice(-5).reverse();
  if(!last.length){
    t.innerHTML='<div style="color:var(--dim)">[--:--:--] System Armed. Awaiting inbound probes...</div>';
    return;
  }
  t.innerHTML=last.map(function(r){
    var c=COL[r[1]]||'--sys';
    var macSuffix=(r[5]&&r[5]!=='--')?' ['+esc(r[5])+']':'';
    return '<div style=color:var('+c+')>['+esc(r[0])+'] <b>'+esc(r[1])+'</b> '+esc(r[2])+macSuffix+' &mdash; '+esc(r[3])+'</div>';
  }).join('');}
function batColor(pct,chg){if(chg)return'#3fb950';if(pct<=5)return'#f85149';if(pct<=15)return'#f0883e';return'#58a6ff';}
function poll(){
  if(!live)return;
  fetch('/api?key='+encodeURIComponent(KEY)).then(function(r){
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  })
  .then(function(d){
    // Metric cards
    ['telnet','ssh','ftp','http','ping','total','creds','scans','boots'].forEach(function(k){
      var e=document.getElementById('c'+k[0].toUpperCase()+k.slice(1));if(e)e.textContent=d[k];});
    document.getElementById('cPayl').textContent=d.payloads;
    document.getElementById('cIps').textContent=(d.ips?d.ips.length:0);

    // Header pills
    var sd=document.getElementById('pSd');
    if(sd){sd.textContent=d.sd?'microSD OK':'RAM Mode (No SD)';sd.className='pill '+(d.sd?'ok':'warn');}
    var bat=document.getElementById('pBat');
    if(d.bat&&bat){
      var bi=d.bat.chg?'⚡':(d.bat.pct>15?'🔋':(d.bat.pct>0?'🪫':'🔌'));
      bat.textContent=bi+' '+d.bat.stat+' ('+d.bat.v+'V)';
      bat.className='pill '+(d.bat.chg?'chg':(d.bat.pct<=5?'bad':(d.bat.pct<=15?'warn':'')));
    }
    document.getElementById('pIp').textContent=d.ip;
    document.getElementById('pUp').textContent='⏱ '+fmtUp(d.up);
    document.getElementById('pRssi').textContent=d.rssi+'dBm';
    document.getElementById('pHeap').textContent=Math.round(d.heap/1024)+'k free';
    document.getElementById('pSeen').style.color='#3fb950';
    document.getElementById('pSeen').title='Last updated: '+new Date().toLocaleTimeString();

    // 1. Service distribution bars
    bars(d);

    // 2. Attackers tab with MAC Address and Threat Level
    var ib=document.getElementById('ipBody');
    if(ib){
      ib.innerHTML=(d.ips&&d.ips.length)?d.ips.map(function(x){
        var isHot=!!x.f;
        var flagBadge=isHot?
          '<span class=badge style="background:var(--scan);color:#060c12">PORT SCANNER (FLAGGED)</span>':
          '<span class=badge style="background:#21262d;color:#8b949e">PROBING</span>';
        var macStr=x.mac||'--';
        return '<tr class="'+(isHot?'hot':'')+'"><td><b>'+esc(x.a)+'</b></td><td><code style="color:#58a6ff;font-size:12px;font-family:monospace">'+esc(macStr)+'</code></td><td>'+svcName(x.m)+
        '</td><td>'+flagBadge+'</td></tr>';
      }).join(''):'<tr><td colspan=4 class=empty>No attackers detected yet</td></tr>';
    }

    // 3. Loot (creds and payloads)
    var cb=document.getElementById('credBody');
    var cl=d.creds_list||[];
    if(cb){
      cb.innerHTML=cl.length?cl.slice().reverse().map(function(r){
        return '<tr><td>'+esc(r.t)+'</td><td><span class=badge style="background:var(--cred)">'+esc(r.s)+'</span></td><td>'+esc(r.a)+'</td><td><b>'+esc(r.u)+'</b></td><td>'+esc(r.p)+'</td></tr>';
      }).join(''):'<tr><td colspan=5 class=empty>No credentials captured yet</td></tr>';
    }
    var pb=document.getElementById('paylBody');
    var pl=d.payloads_list||[];
    if(pb){
      pb.innerHTML=pl.length?pl.slice().reverse().map(function(r){
        return '<tr><td>'+esc(r.t)+'</td><td><span class=badge style="background:var(--cred)">'+esc(r.s)+'</span></td><td>'+esc(r.a)+'</td><td class=det><code>'+esc(r.c)+'</code></td></tr>';
      }).join(''):'<tr><td colspan=4 class=empty>No payloads captured yet</td></tr>';
    }

    // 4. Events -> Threat Feed Ticker & Threat Log Table
    if(d.events&&d.events.length){
      rows=d.events.map(function(e){return [e.t,e.s,e.a,e.d,e.h,e.mac||'--'];});
      draw();
      updateTicker(rows);
    }

    // 5. Battery and system tab
    if(d.bat){
      var bc=batColor(d.bat.pct,d.bat.chg);
      document.getElementById('batFill').style.cssText='width:'+d.bat.pct+'%;background:'+bc;
      document.getElementById('batV').textContent=d.bat.v+' V';
      document.getElementById('batPct').textContent=d.bat.pct+'%';
      document.getElementById('batStat').textContent=d.bat.stat;
      document.getElementById('batStat').style.color=bc;
    }
    document.getElementById('sIp').textContent=d.ip;
    document.getElementById('sRssi').textContent=d.rssi+' dBm';
    document.getElementById('sHeap').textContent=Math.round(d.heap/1024)+' kB';
    document.getElementById('sUp').textContent=fmtUp(d.up);
    document.getElementById('sBoots').textContent=d.boots;
    document.getElementById('sSd').textContent=d.sd?'Card OK — FAT32':'RAM Mode (No SD)';
    if(d.ssid){
      var ws=document.getElementById('wCurSsid');if(ws)ws.textContent=d.ssid;
      var st=document.getElementById('wCurStat');if(st){st.textContent=d.ssid==='Offline'?'Offline':'Connected';st.style.color=d.ssid==='Offline'?'var(--cred)':'#3fb950';}
    }
  }).catch(function(){document.getElementById('pSeen').style.color='var(--cred)';});
}
poll();setInterval(poll,2500);
</script></body></html>)HTML";

/* ── Wi-Fi Configuration State & UI Handles ── */
static char wifiPendingSsid[64] = "";
static char wifiPendingPass[64] = "";
static volatile bool wifiIsScanning = false;
static volatile bool wifiIsConnecting = false;

static lv_obj_t *lblWifiStatus = nullptr;
static lv_obj_t *lblWifiCur = nullptr;
static lv_obj_t *lblWifiPill = nullptr;
static lv_obj_t *ddWifiSsid = nullptr;
static lv_obj_t *taWifiSsid = nullptr;
static lv_obj_t *taWifiPass = nullptr;
static lv_obj_t *btnWifiScan = nullptr;
static lv_obj_t *lblWifiScanBtn = nullptr;
static lv_obj_t *btnWifiShowPass = nullptr;
static lv_obj_t *lblWifiShowPassBtn = nullptr;
static lv_obj_t *btnWifiConnect = nullptr;
static lv_obj_t *lblWifiConnBtn = nullptr;
static lv_obj_t *cardWifi = nullptr;
static lv_obj_t *lblWifiTitle = nullptr;

// On-screen capacitive virtual keyboard modal & live preview bar
static lv_obj_t *kbModal = nullptr;
static lv_obj_t *lblKbPrompt = nullptr;
static lv_obj_t *taKbInput = nullptr;
static lv_obj_t *btnKbShowPass = nullptr;
static lv_obj_t *lblKbShowPass = nullptr;
static lv_obj_t *btnKbDone = nullptr;
static lv_obj_t *btnKbCancel = nullptr;
static lv_obj_t *kbWifi = nullptr;
static lv_obj_t *activeTargetTa = nullptr;

void wifiScanTask(void *param) {
  wifiIsScanning = true;
  Serial.println("[WIFI] Manual AP scan initiated...");

  if (esp_lv_adapter_lock(-1)) {
    if (lblWifiStatus) {
      lv_label_set_text(lblWifiStatus, "Scanning 2.4GHz Wi-Fi networks...");
      lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xD29922), 0);
    }
    if (lblWifiScanBtn) {
      lv_label_set_text(lblWifiScanBtn, "Scanning...");
    }
    esp_lv_adapter_unlock();
  }

  // 1. Ensure WiFi hardware is awake and in STA mode with RAM-only storage
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (!(WiFi.getMode() & WIFI_STA)) {
    WiFi.mode(WIFI_STA);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    delay(60);
  }

  // 2. Disconnect any active link without de-initializing the network interface
  esp_wifi_disconnect();
  delay(100);

  // 3. Clear any previous scan buffer
  WiFi.scanDelete();

  // 4. Perform synchronous scan (running inside this FreeRTOS task)
  int16_t n = WiFi.scanNetworks(false, false, false, 300);
  Serial.printf("[WIFI] Initial scan returned: %d APs\n", n);

  // If radio was busy or state was transient, retry once after a brief rest
  if (n < 0) {
    Serial.println("[WIFI] Scan returned error code, retrying scan...");
    esp_wifi_disconnect();
    delay(150);
    WiFi.scanDelete();
    n = WiFi.scanNetworks(false, false, false, 300);
    Serial.printf("[WIFI] Retry scan returned: %d APs\n", n);
  }

  if (esp_lv_adapter_lock(-1)) {
    if (lblWifiScanBtn) {
      lv_label_set_text(lblWifiScanBtn, "🔍 Scan APs");
    }
    if (n < 0) {
      if (lblWifiStatus) {
        lv_label_set_text(lblWifiStatus, "Scan failed. Please tap 'Scan APs' again.");
        lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xF85149), 0);
      }
    } else if (n == 0) {
      if (lblWifiStatus) {
        lv_label_set_text(lblWifiStatus, "No 2.4GHz Wi-Fi networks found.");
        lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xD29922), 0);
      }
      if (ddWifiSsid) {
        lv_dropdown_set_options(ddWifiSsid, "-- No networks detected --");
      }
    } else {
      String apList = "";
      for (int i = 0; i < n; i++) {
        String s = WiFi.SSID(i);
        if (s.length() == 0) continue; // Skip hidden/empty SSIDs
        String checkStr = s + " (";
        if (apList.indexOf(checkStr) >= 0) continue; // Deduplicate

        if (apList.length() > 0) apList += "\n";
        apList += s + " (" + String(WiFi.RSSI(i)) + "dBm)";
        Serial.printf("   [AP #%d] %s (%d dBm)\n", i, s.c_str(), WiFi.RSSI(i));
      }
      if (apList.length() == 0) {
        apList = "-- No broadcasted SSIDs --";
      }
      if (ddWifiSsid) {
        lv_dropdown_set_options(ddWifiSsid, apList.c_str());
      }
      if (lblWifiStatus) {
        char sbuf[64];
        snprintf(sbuf, sizeof(sbuf), "Found %d networks. Select AP or type SSID.", n);
        lv_label_set_text(lblWifiStatus, sbuf);
        lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0x3FB950), 0);
      }
    }
    esp_lv_adapter_unlock();
  }

  wifiIsScanning = false;
  vTaskDelete(NULL);
}

void wifiConnectTask(void *param) {
  wifiIsConnecting = true;
  Serial.printf("[WIFI] Connecting to '%s'...\n", wifiPendingSsid);
  if (esp_lv_adapter_lock(-1)) {
    if (lblWifiStatus) {
      char sbuf[96];
      snprintf(sbuf, sizeof(sbuf), "Connecting to '%s'...", wifiPendingSsid);
      lv_label_set_text(lblWifiStatus, sbuf);
      lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xD29922), 0);
    }
    esp_lv_adapter_unlock();
  }

  // Ensure RAM-only storage so IDF never writes flash (prevents cache disable panics)
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_disconnect();
  delay(100);

  WiFi.mode(WIFI_STA);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  WiFi.begin(wifiPendingSsid, wifiPendingPass);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 12000) {
    delay(250);
  }

  if (esp_lv_adapter_lock(-1)) {
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf("[WIFI] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
      saveWifiConfig(wifiPendingSsid, wifiPendingPass);
      if (lblWifiStatus) {
        char sbuf[96];
        snprintf(sbuf, sizeof(sbuf), "Connected! IP: %s (%ddBm)",
                 WiFi.localIP().toString().c_str(), WiFi.RSSI());
        lv_label_set_text(lblWifiStatus, sbuf);
        lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0x3FB950), 0);
      }
      if (lblWifiCur) {
        char cbuf[96];
        snprintf(cbuf, sizeof(cbuf), "SSID: %s  |  IP: %s (%ddBm)",
                 WiFi.SSID().c_str(), WiFi.localIP().toString().c_str(), WiFi.RSSI());
        lv_label_set_text(lblWifiCur, cbuf);
      }
      if (lblWifiPill) {
        char pbuf[32];
        snprintf(pbuf, sizeof(pbuf), "%s (%ddBm)", WiFi.SSID().c_str(), WiFi.RSSI());
        lv_label_set_text(lblWifiPill, pbuf);
      }
      configTime(GMT_OFFSET_SEC, DST_OFFSET_SEC, "pool.ntp.org", "time.nist.gov");
      ntpConfigured = true;
    } else {
      Serial.printf("[WIFI] Connection to '%s' failed.\n", wifiPendingSsid);
      if (lblWifiStatus) {
        char sbuf[96];
        snprintf(sbuf, sizeof(sbuf), "Connection failed. Check credentials.");
        lv_label_set_text(lblWifiStatus, sbuf);
        lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xF85149), 0);
      }
    }
    esp_lv_adapter_unlock();
  }
  wifiIsConnecting = false;
  vTaskDelete(NULL);
}

void handleAdmin() {
  WiFiClient c = srvAccept(srvAdmin);
  if (!c) return;
  String req;
  uint32_t t0 = millis();
  while ((millis() - t0) < 1500 && c.connected()) {
    if (c.available()) {
      char ch = c.read();
      if (ch == '\n') break;
      req += ch;
    } else {
      delay(2);
    }
  }
  while (c.available()) c.read();

  // ── Serve login page at / (no key required) ──
  bool isRoot = (req.indexOf("GET / ") >= 0 || req.indexOf("GET /\r") >= 0);
  if (isRoot && req.indexOf(ADMIN_KEY) < 0) {
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    c.print(LOGIN_HTML);
    c.flush();
    delay(15); c.stop(); return;
  }

  // ── All other routes require the key ──
  if (req.indexOf(ADMIN_KEY) < 0) {
    c.print("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nnope\r\n");
    c.flush();
    delay(5); c.stop(); return;
  }

  // ── /api ──
  if (req.indexOf("/api") >= 0) {
    String j = "{";
    j += "\"sd\":";       j += (sdOk ? "true" : "false");
    j += ",\"ip\":\"" + WiFi.localIP().toString() + "\"";
    j += ",\"rssi\":"   + String(WiFi.RSSI());
    j += ",\"heap\":"   + String(ESP.getFreeHeap());
    j += ",\"ssid\":\"" + escapeJson(WiFi.status() == WL_CONNECTED ? WiFi.SSID() : String("Offline")) + "\"";
    j += ",\"up\":"     + String(millis() / 1000);
    j += ",\"boots\":"  + String(st.boots);
    j += ",\"telnet\":" + String(st.telnet);
    j += ",\"ssh\":"    + String(st.ssh);
    j += ",\"ftp\":"    + String(st.ftp);
    j += ",\"http\":"   + String(st.http);
    j += ",\"ping\":"   + String(st.ping);
    j += ",\"total\":"  + String(st.total);
    j += ",\"creds\":"  + String(st.creds);
    j += ",\"payloads\":" + String(st.payloads);
    j += ",\"scans\":"  + String(st.scans);
    j += ",\"bat\":{\"v\":" + String(curBat.voltage, 2) +
         ",\"pct\":" + String(curBat.percent) +
         ",\"chg\":" + (curBat.charging ? "true" : "false") +
         ",\"stat\":\"" + escapeJson(curBat.status) + "\"}";
    j += ",\"ips\":[";
    for (uint8_t i = 0; i < ipCount; i++) {
      IPAddress a(ipTab[i].ip);
      if (i) j += ",";
      j += "{\"a\":\"" + a.toString() + "\",\"mac\":\"" + escapeJson(ipTab[i].mac[0] ? ipTab[i].mac : "--") + "\",\"m\":" + String(ipTab[i].mask) +
           ",\"f\":" + String(ipTab[i].flagged ? "true" : "false") + "}";
    }
    j += "]";
    // Captured credentials
    j += ",\"creds_list\":[";
    for (uint8_t i = 0; i < credCount; i++) {
      if (i) j += ",";
      j += "{\"t\":\"" + escapeJson(credTab[i].time) + "\",\"s\":\"" + escapeJson(credTab[i].svc) +
           "\",\"a\":\"" + escapeJson(credTab[i].ip)  + "\",\"u\":\"" + escapeJson(credTab[i].user) +
           "\",\"p\":\"" + escapeJson(credTab[i].pass) + "\"}";
    }
    j += "]";
    // Captured payloads
    j += ",\"payloads_list\":[";
    for (uint8_t i = 0; i < payloadCount; i++) {
      if (i) j += ",";
      j += "{\"t\":\"" + escapeJson(payloadTab[i].time) + "\",\"s\":\"" + escapeJson(payloadTab[i].svc) +
           "\",\"a\":\"" + escapeJson(payloadTab[i].ip)  + "\",\"c\":\"" + escapeJson(payloadTab[i].cmd) + "\"}";
    }
    j += "]";
    // Events list
    j += ",\"events\":[";
    for (uint8_t i = 0; i < logCount; i++) {
      if (i) j += ",";
      j += "{\"t\":\"" + escapeJson(logEntries[i].time) + "\",\"s\":\"" + escapeJson(logEntries[i].svc) +
           "\",\"a\":\"" + escapeJson(logEntries[i].ip) + "\",\"mac\":\"" + escapeJson(logEntries[i].mac[0] ? logEntries[i].mac : "--") + "\",\"d\":\"" + escapeJson(logEntries[i].detail) +
           "\",\"h\":" + (logEntries[i].isAlert ? "true" : "false") + "}";
    }
    j += "]}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    c.print(j);
    c.flush();
    delay(10); c.stop(); return;
  }

  // ── /loot — JSON array of captured credentials and payloads ──
  if (req.indexOf("/loot") >= 0) {
    String j = "{\"creds\":[";
    for (uint8_t i = 0; i < credCount; i++) {
      if (i) j += ",";
      j += "{\"t\":\"" + escapeJson(credTab[i].time) + "\",\"s\":\"" + escapeJson(credTab[i].svc) +
           "\",\"a\":\"" + escapeJson(credTab[i].ip)  + "\",\"u\":\"" + escapeJson(credTab[i].user) +
           "\",\"p\":\"" + escapeJson(credTab[i].pass) + "\"}";
    }
    j += "],\"payloads\":[";
    for (uint8_t i = 0; i < payloadCount; i++) {
      if (i) j += ",";
      j += "{\"t\":\"" + escapeJson(payloadTab[i].time) + "\",\"s\":\"" + escapeJson(payloadTab[i].svc) +
           "\",\"a\":\"" + escapeJson(payloadTab[i].ip)  + "\",\"c\":\"" + escapeJson(payloadTab[i].cmd) + "\"}";
    }
    j += "]}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    c.print(j);
    c.flush();
    delay(10); c.stop(); return;
  }

  // ── /tail ──
  if (req.indexOf("/tail") >= 0) {
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    bool sentAny = false;
    if (sdOk && SD_MMC.exists(LOG_PATH)) {
      fs::File f = SD_MMC.open(LOG_PATH, FILE_READ);
      if (f && f.size() > 0) {
        sentAny = true;
        const size_t WANT = 14000;
        if ((size_t)f.size() > WANT) {
          f.seek(f.size() - WANT);
          while (f.available()) { if (f.read() == '\n') break; }
        }
        uint8_t buf[256];
        while (f.available()) { size_t n = f.read(buf, 256); c.write(buf, n); }
        f.close();
      }
    }
    if (!sentAny) {
      for (uint8_t i = 0; i < logCount; i++) {
        c.printf("%s\t%s\t%s\t%s\t%s\n", logEntries[i].time, logEntries[i].svc, logEntries[i].ip, logEntries[i].mac[0] ? logEntries[i].mac : "--", logEntries[i].detail);
      }
    }
    c.flush();
    delay(10); c.stop(); return;
  }

  // ── /raw ──
  if (req.indexOf("/raw") >= 0) {
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=vera.tsv\r\nConnection: close\r\n\r\n");
    if (sdOk && SD_MMC.exists(LOG_PATH)) {
      fs::File f = SD_MMC.open(LOG_PATH, FILE_READ);
      if (f) {
        uint8_t buf[256];
        while (f.available()) { size_t n = f.read(buf, 256); c.write(buf, n); }
        f.close();
      }
    } else {
      for (uint8_t i = 0; i < logCount; i++) {
        c.printf("%s\t%s\t%s\t%s\t%s\n", logEntries[i].time, logEntries[i].svc, logEntries[i].ip, logEntries[i].mac[0] ? logEntries[i].mac : "--", logEntries[i].detail);
      }
    }
    c.flush();
    delay(10); c.stop(); return;
  }

  // ── /clear ──
  if (req.indexOf("/clear") >= 0) {
    if (sdOk) { SD_MMC.remove(LOG_PATH); SD_MMC.remove(STATE_PATH); }
    memset(&st, 0, sizeof(st));
    ipCount = 0; credCount = 0; payloadCount = 0; logCount = 0;
    updateDashboardMetrics(); updateIpTableUI(); updateLootUI();
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ncleared\r\n");
    c.flush();
    delay(5); c.stop(); return;
  }

  // ── /wifi/scan ──
  if (req.indexOf("/wifi/scan") >= 0) {
    WiFi.scanDelete();
    int16_t n = WiFi.scanNetworks(false, false, false, 150);
    if (n < 0) {
      delay(80);
      WiFi.scanDelete();
      n = WiFi.scanNetworks(false, false, false, 150);
    }
    String j = "{\"nets\":[";
    int added = 0;
    for (int i = 0; i < n; i++) {
      String s = WiFi.SSID(i);
      if (s.length() == 0) continue;
      if (added > 0) j += ",";
      j += "{\"ssid\":\"" + escapeJson(s) + "\",\"rssi\":" + String(WiFi.RSSI(i)) + "}";
      added++;
    }
    j += "]}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    c.print(j);
    c.flush();
    delay(15); c.stop(); return;
  }

  // ── /wifi/connect ──
  if (req.indexOf("/wifi/connect") >= 0) {
    String nSsid = formField(req, "ssid");
    String nPass = formField(req, "pass");
    if (nSsid.length() > 0) {
      strncpy(wifiPendingSsid, nSsid.c_str(), sizeof(wifiPendingSsid) - 1);
      wifiPendingSsid[sizeof(wifiPendingSsid) - 1] = '\0';
      strncpy(wifiPendingPass, nPass.c_str(), sizeof(wifiPendingPass) - 1);
      wifiPendingPass[sizeof(wifiPendingPass) - 1] = '\0';
      c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
      c.print("{\"ok\":true,\"msg\":\"Connecting to " + escapeJson(nSsid) + "... Check device screen for IP.\"}");
      c.flush();
      delay(20); c.stop();
      xTaskCreate(wifiConnectTask, "w_conn", 6144, NULL, 1, NULL);
      return;
    } else {
      c.print("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":false,\"msg\":\"Missing SSID\"}");
      c.flush();
      delay(10); c.stop();
      return;
    }
  }

  // ── /ui — full mirrored dashboard ──
  c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
  c.print(DASH_HTML);
  c.flush();
  delay(25); c.stop();
}


/*=================== 14. LVGL GUI DESIGN (1024x600) ============*/
static lv_obj_t *scr;
static lv_obj_t *hdr;
static lv_obj_t *tabview;
static lv_obj_t *lblTitle;
static lv_obj_t *btnTheme;
static lv_obj_t *lblThemeBtn;
static lv_obj_t *lblClock;
static lv_obj_t *lblBatteryPill;
static lv_obj_t *lblSdBadge;
static lv_obj_t *lblHeapPill;

/* Battery UI widgets in System Tab */
static lv_obj_t *barBattery;
static lv_obj_t *lblBatVoltageVal;
static lv_obj_t *lblBatPctVal;
static lv_obj_t *lblBatStatusVal;
static lv_obj_t *lblBatAdcVal;

/* UI Theme Tracking */
static lv_obj_t *btnThemeSettings;
static lv_obj_t *lblThemeSettingsBtn;
static lv_obj_t *lblThemeModeInfo;
static lv_obj_t *uiCards[24];
static uint8_t uiCardCount = 0;
static lv_obj_t *uiValLabels[24];
static uint8_t uiValLabelCount = 0;

struct MetricCardWidgets {
  lv_obj_t *card;
  lv_obj_t *lblTitle;
  lv_obj_t *lblVal;
  uint32_t darkColor;
  uint32_t lightColor;
};
static MetricCardWidgets metricCards[10];
static uint8_t metricCardCount = 0;

struct DistBarWidgets {
  lv_obj_t *bar;
  lv_obj_t *lblTitle;
  lv_obj_t *lblVal;
  uint32_t darkColor;
  uint32_t lightColor;
};
static DistBarWidgets distBars[5];
static uint8_t distBarCount = 0;

/* Stat labels on Overview Tab */
static lv_obj_t *lblValTelnet, *lblValSsh, *lblValFtp, *lblValHttp, *lblValPing;
static lv_obj_t *lblValTotal, *lblValIps, *lblValCreds, *lblValPayloads, *lblValScans;
static lv_obj_t *barTelnet, *barSsh, *barFtp, *barHttp, *barPing;
static lv_obj_t *lblBarTelnet, *lblBarSsh, *lblBarFtp, *lblBarHttp, *lblBarPing;
static lv_obj_t *lblRecentTickers[4];
static lv_obj_t *lblDistT;
static lv_obj_t *lblTickT;
static lv_obj_t *lblCrT;
static lv_obj_t *lblPlT;
static lv_obj_t *lblSysT;
static lv_obj_t *lblBatT;
static lv_obj_t *lblBlt;
static lv_obj_t *lblThemeSec;
static lv_obj_t *lblBatK1, *lblBatK2;
static lv_obj_t *lblBatDetails;
static lv_obj_t *lblDistNames[5];

/* Threat Log Tab */
static lv_obj_t *tableLog;
static lv_obj_t *btnFilterHot;
static bool filterAlertsOnly = false;

/* IP Table Tab */
static lv_obj_t *tableIps;

/* Loot Tab */
static lv_obj_t *tableCreds;
static lv_obj_t *tablePayloads;

/* Settings Tab */
static lv_obj_t *sliderBrightness;
static lv_obj_t *lblBrightnessVal;
static lv_obj_t *lblSdInfo;

/* Reusable styles */
static lv_style_t style_card_dark, style_card_light;
static lv_style_t style_hdr_dark, style_hdr_light;
static lv_style_t style_scr_dark, style_scr_light;

/* Theme Toggle Button Callback */
static void onThemeToggleClicked(lv_event_t *e) {
  isDarkMode = !isDarkMode;
  applyTheme(isDarkMode);
  saveState(true);
}

/* Brightness Slider Callback */
static void onBrightnessSliderChanged(lv_event_t *e) {
  lv_obj_t *slider = lv_event_get_target(e);
  int val = (int)lv_slider_get_value(slider);
  currentBrightness = (uint8_t)val;
  IO_EXTENSION_Pwm_Output(currentBrightness);
  if (lblBrightnessVal) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d%%", currentBrightness);
    lv_label_set_text(lblBrightnessVal, buf);
  }
}

/* Log row click -> Detailed Popup Callback */
static void onLogTableClicked(lv_event_t *e) {
  lv_obj_t *table = lv_event_get_target(e);
  uint16_t row, col;
  lv_table_get_selected_cell(table, &row, &col);
  if (row >= logCount) return;

  // Find corresponding log entry
  int idx = logCount - 1 - row;
  if (idx < 0 || idx >= logCount) return;
  const LogEntry &entry = logEntries[idx];

  char msg[256];
  snprintf(msg, sizeof(msg), "Time: %s\nService: %s\nSource IP: %s\nMAC: %s\n\nDetail:\n%s",
           entry.time, entry.svc, entry.ip, (entry.mac[0] ? entry.mac : "--"), entry.detail);

  static const char *btns[] = {"Dismiss", ""};
  lv_obj_t *mbox = lv_msgbox_create(NULL, "Threat Inspection", msg, btns, true);
  lv_obj_center(mbox);
}

/* Clear state button callback */
static void onClearBtnClicked(lv_event_t *e) {
  if (sdOk) {
    SD_MMC.remove(LOG_PATH);
    SD_MMC.remove(STATE_PATH);
  }
  memset(&st, 0, sizeof(st));
  ipCount = 0;
  credCount = 0;
  payloadCount = 0;
  logCount = 0;
  updateDashboardMetrics();
  updateIpTableUI();
  updateLootUI();

  static const char *btns[] = {"OK", ""};
  lv_obj_t *mbox = lv_msgbox_create(NULL, "Reset Completed", "Log and state files have been cleared.", btns, true);
  lv_obj_center(mbox);
}

/* Wi-Fi Configuration & Virtual Keyboard Event Callbacks */
static void onWifiScanClicked(lv_event_t *e) {
  if (wifiIsScanning) return;
  xTaskCreate(wifiScanTask, "w_scan", 8192, NULL, 1, NULL);
}

static void onWifiDropdownChanged(lv_event_t *e) {
  lv_obj_t *dropdown = lv_event_get_target(e);
  char buf[64];
  lv_dropdown_get_selected_str(dropdown, buf, sizeof(buf));
  char *paren = strchr(buf, '(');
  if (paren && paren > buf) {
    *(paren - 1) = '\0';
  }
  int len = strlen(buf);
  while (len > 0 && (buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
    buf[len - 1] = '\0';
    len--;
  }
  if (taWifiSsid && buf[0] != '-' && buf[0] != '\0') {
    lv_textarea_set_text(taWifiSsid, buf);
    strncpy(curWifiSsid, buf, sizeof(curWifiSsid) - 1);
    curWifiSsid[sizeof(curWifiSsid) - 1] = '\0';
    if (lblWifiStatus) {
      char sbuf[96];
      snprintf(sbuf, sizeof(sbuf), "Selected '%s'. Enter password & connect.", buf);
      lv_label_set_text(lblWifiStatus, sbuf);
      lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0x58A6FF), 0);
    }
  }
}

static void closeKbModal(bool apply) {
  if (!kbModal) return;
  if (apply && activeTargetTa && taKbInput) {
    const char *txt = lv_textarea_get_text(taKbInput);
    lv_textarea_set_text(activeTargetTa, txt ? txt : "");
    if (activeTargetTa == taWifiSsid) {
      strncpy(curWifiSsid, txt ? txt : "", sizeof(curWifiSsid) - 1);
      curWifiSsid[sizeof(curWifiSsid) - 1] = '\0';
    } else if (activeTargetTa == taWifiPass) {
      strncpy(curWifiPass, txt ? txt : "", sizeof(curWifiPass) - 1);
      curWifiPass[sizeof(curWifiPass) - 1] = '\0';
    }
  }
  lv_obj_add_flag(kbModal, LV_OBJ_FLAG_HIDDEN);
  activeTargetTa = nullptr;
}

static void onKbDoneClicked(lv_event_t *e) {
  closeKbModal(true);
}

static void onKbCancelClicked(lv_event_t *e) {
  closeKbModal(false);
}

static void onKbTogglePassClicked(lv_event_t *e) {
  if (!taKbInput) return;
  bool pwdMode = lv_textarea_get_password_mode(taKbInput);
  lv_textarea_set_password_mode(taKbInput, !pwdMode);
  if (lblKbShowPass) {
    lv_label_set_text(lblKbShowPass, !pwdMode ? "Hide" : "Show");
  }
}

static void onWifiInputFocused(lv_event_t *e) {
  lv_obj_t *ta = lv_event_get_target(e);
  if (!kbModal || !taKbInput) return;

  activeTargetTa = ta;
  const char *curr = lv_textarea_get_text(ta);
  lv_textarea_set_text(taKbInput, curr ? curr : "");

  if (ta == taWifiPass) {
    if (lblKbPrompt) lv_label_set_text(lblKbPrompt, "PASSWORD:");
    lv_textarea_set_password_mode(taKbInput, true);
    if (lblKbShowPass) lv_label_set_text(lblKbShowPass, "Show");
    if (btnKbShowPass) lv_obj_clear_flag(btnKbShowPass, LV_OBJ_FLAG_HIDDEN);
  } else {
    if (lblKbPrompt) lv_label_set_text(lblKbPrompt, "SSID:");
    lv_textarea_set_password_mode(taKbInput, false);
    if (btnKbShowPass) lv_obj_add_flag(btnKbShowPass, LV_OBJ_FLAG_HIDDEN);
  }

  lv_keyboard_set_textarea(kbWifi, taKbInput);
  lv_keyboard_set_mode(kbWifi, LV_KEYBOARD_MODE_TEXT_LOWER);
  lv_obj_clear_flag(kbModal, LV_OBJ_FLAG_HIDDEN);
  lv_obj_move_foreground(kbModal);
}

static void onWifiKeyboardAction(lv_event_t *e) {
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_READY) {
    closeKbModal(true);
  } else if (code == LV_EVENT_CANCEL) {
    closeKbModal(false);
  }
}

static void onWifiConnectClicked(lv_event_t *e) {
  if (wifiIsConnecting || wifiIsScanning) return;
  if (!taWifiSsid || !taWifiPass) return;
  const char *s = lv_textarea_get_text(taWifiSsid);
  const char *p = lv_textarea_get_text(taWifiPass);
  if (!s || !s[0]) {
    if (lblWifiStatus) {
      lv_label_set_text(lblWifiStatus, "Please select or type an SSID.");
      lv_obj_set_style_text_color(lblWifiStatus, lv_color_hex(0xF85149), 0);
    }
    return;
  }
  strncpy(wifiPendingSsid, s, sizeof(wifiPendingSsid) - 1);
  wifiPendingSsid[sizeof(wifiPendingSsid) - 1] = '\0';
  strncpy(wifiPendingPass, p ? p : "", sizeof(wifiPendingPass) - 1);
  wifiPendingPass[sizeof(wifiPendingPass) - 1] = '\0';
  if (kbModal) lv_obj_add_flag(kbModal, LV_OBJ_FLAG_HIDDEN);
  xTaskCreate(wifiConnectTask, "w_conn", 6144, NULL, 1, NULL);
}

static void onWifiShowPassClicked(lv_event_t *e) {
  if (!taWifiPass) return;
  bool pwdMode = lv_textarea_get_password_mode(taWifiPass);
  lv_textarea_set_password_mode(taWifiPass, !pwdMode);
  if (lblWifiShowPassBtn) {
    lv_label_set_text(lblWifiShowPassBtn, !pwdMode ? "Hide" : "Show");
  }
}

/* Helper to build a metric card */
static lv_obj_t* createMetricCard(lv_obj_t *parent, const char *title, uint32_t darkCol, uint32_t lightCol, lv_obj_t **outValLabel) {
  uint32_t col = isDarkMode ? darkCol : lightCol;
  lv_obj_t *card = lv_obj_create(parent);
  lv_obj_set_size(card, 185, 96);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_pad_all(card, 8, 0);
  lv_obj_set_style_radius(card, 8, 0);
  lv_obj_set_style_border_width(card, 2, 0);
  lv_obj_set_style_border_color(card, lv_color_hex(col), 0);
  lv_obj_set_style_bg_color(card, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);

  lv_obj_t *lblT = lv_label_create(card);
  lv_label_set_text(lblT, title);
  lv_obj_set_style_text_color(lblT, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(lblT, &lv_font_montserrat_12, 0);
  lv_obj_align(lblT, LV_ALIGN_TOP_LEFT, 0, 0);

  lv_obj_t *lblV = lv_label_create(card);
  lv_label_set_text(lblV, "0");
  lv_obj_set_style_text_font(lblV, &lv_font_montserrat_28, 0);
  lv_obj_set_style_text_color(lblV, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblV, LV_ALIGN_BOTTOM_LEFT, 0, 0);

  if (metricCardCount < 10) {
    metricCards[metricCardCount++] = {card, lblT, lblV, darkCol, lightCol};
  }

  if (outValLabel) *outValLabel = lblV;
  return card;
}

/* Apply Dark vs Light Theme Styles */
void applyTheme(bool dark) {
  if (!esp_lv_adapter_lock(200)) return;

  lv_color_t c_bg   = dark ? lv_color_hex(0x0B0F14) : lv_color_hex(0xF0F2F5);
  lv_color_t c_hdr  = dark ? lv_color_hex(0x161B22) : lv_color_hex(0xE1E4E8);
  lv_color_t c_card = dark ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF);
  lv_color_t c_txt  = dark ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328);
  lv_color_t c_dim  = dark ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F);

  if (scr) lv_obj_set_style_bg_color(scr, c_bg, 0);
  if (hdr) lv_obj_set_style_bg_color(hdr, c_hdr, 0);

  if (lblTitle) lv_obj_set_style_text_color(lblTitle, dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  if (lblClock) lv_obj_set_style_text_color(lblClock, c_txt, 0);

  if (btnTheme && lblThemeBtn) {
    lv_label_set_text(lblThemeBtn, dark ? "☀️ LIGHT" : "🌙 DARK");
    lv_obj_set_style_bg_color(btnTheme, dark ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
    lv_obj_set_style_text_color(lblThemeBtn, c_txt, 0);
    lv_obj_set_style_border_color(btnTheme, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  }

  if (btnThemeSettings && lblThemeSettingsBtn) {
    lv_label_set_text(lblThemeSettingsBtn, dark ? "Switch to Light UI" : "Switch to Dark UI");
    lv_obj_set_style_bg_color(btnThemeSettings, dark ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
    lv_obj_set_style_text_color(lblThemeSettingsBtn, c_txt, 0);
    lv_obj_set_style_border_color(btnThemeSettings, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  }
  if (lblThemeModeInfo) {
    lv_label_set_text(lblThemeModeInfo, dark ? "Current Mode: DARK (Cyber SOC)" : "Current Mode: LIGHT (Daylight)");
    lv_obj_set_style_text_color(lblThemeModeInfo, c_txt, 0);
  }

  if (tabview) {
    lv_obj_set_style_bg_color(tabview, c_bg, 0);
    lv_obj_t *tab_btns = lv_tabview_get_tab_btns(tabview);
    if (tab_btns) {
      lv_obj_set_style_bg_color(tab_btns, c_hdr, 0);
      lv_obj_set_style_text_color(tab_btns, c_txt, 0);
    }
  }

  // Update registered container cards
  for (uint8_t i = 0; i < uiCardCount; i++) {
    if (uiCards[i]) {
      lv_obj_set_style_bg_color(uiCards[i], c_card, 0);
      lv_obj_set_style_border_color(uiCards[i], dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
    }
  }

  // Update Metric Cards (Card bg, border color, title color, value text color)
  for (uint8_t i = 0; i < metricCardCount; i++) {
    uint32_t col = dark ? metricCards[i].darkColor : metricCards[i].lightColor;
    lv_obj_set_style_bg_color(metricCards[i].card, c_card, 0);
    lv_obj_set_style_border_color(metricCards[i].card, lv_color_hex(col), 0);
    lv_obj_set_style_text_color(metricCards[i].lblTitle, lv_color_hex(col), 0);
    lv_obj_set_style_text_color(metricCards[i].lblVal, c_txt, 0);
  }

  // Update tables
  auto styleTable = [&](lv_obj_t *tbl) {
    if (!tbl) return;
    lv_obj_set_style_bg_color(tbl, c_card, LV_PART_MAIN);
    lv_obj_set_style_text_color(tbl, c_txt, LV_PART_MAIN);
    lv_obj_set_style_bg_color(tbl, c_card, LV_PART_ITEMS);
    lv_obj_set_style_text_color(tbl, c_txt, LV_PART_ITEMS);
    lv_obj_set_style_border_color(tbl, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), LV_PART_MAIN);
    lv_obj_set_style_border_color(tbl, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), LV_PART_ITEMS);
  };
  styleTable(tableLog);
  styleTable(tableIps);
  styleTable(tableCreds);
  styleTable(tablePayloads);

  // Update Service Distribution Bars, Borders, Indicators & Count Labels
  lv_color_t c_bar_bg = dark ? lv_color_hex(0x21262D) : lv_color_hex(0xEAEEF2);
  lv_color_t c_bar_border = dark ? lv_color_hex(0x8B949E) : lv_color_hex(0x57606A);
  for (uint8_t i = 0; i < distBarCount; i++) {
    uint32_t col = dark ? distBars[i].darkColor : distBars[i].lightColor;
    lv_obj_set_style_bg_color(distBars[i].bar, c_bar_bg, 0);
    lv_obj_set_style_border_color(distBars[i].bar, c_bar_border, 0);
    lv_obj_set_style_border_width(distBars[i].bar, 2, 0);
    lv_obj_set_style_pad_all(distBars[i].bar, 1, 0);
    lv_obj_set_style_bg_color(distBars[i].bar, lv_color_hex(col), LV_PART_INDICATOR);
    lv_obj_set_style_text_color(distBars[i].lblTitle, lv_color_hex(col), 0);
    lv_obj_set_style_text_color(distBars[i].lblVal, c_txt, 0);
  }

  if (barBattery) {
    lv_obj_set_style_bg_color(barBattery, c_bar_bg, 0);
    lv_obj_set_style_border_color(barBattery, c_bar_border, 0);
    lv_obj_set_style_border_width(barBattery, 2, 0);
    lv_obj_set_style_pad_all(barBattery, 1, 0);
  }

  // Section titles
  if (lblDistT) lv_obj_set_style_text_color(lblDistT, dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  if (lblTickT) lv_obj_set_style_text_color(lblTickT, dark ? lv_color_hex(0xF85149) : lv_color_hex(0xA40E26), 0);
  if (lblCrT)   lv_obj_set_style_text_color(lblCrT,   dark ? lv_color_hex(0xF85149) : lv_color_hex(0xA40E26), 0);
  if (lblPlT)   lv_obj_set_style_text_color(lblPlT,   dark ? lv_color_hex(0xF85149) : lv_color_hex(0xA40E26), 0);
  if (lblSysT)  lv_obj_set_style_text_color(lblSysT,  dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  if (lblBatT)  lv_obj_set_style_text_color(lblBatT,  dark ? lv_color_hex(0x3FB950) : lv_color_hex(0x0F5323), 0);

  // System & Settings labels
  if (lblBlt)           lv_obj_set_style_text_color(lblBlt, c_txt, 0);
  if (lblBrightnessVal) lv_obj_set_style_text_color(lblBrightnessVal, c_txt, 0);
  if (lblThemeSec)      lv_obj_set_style_text_color(lblThemeSec, c_txt, 0);
  if (lblSdInfo)        lv_obj_set_style_text_color(lblSdInfo, c_dim, 0);

  // Telemetry and Battery labels
  if (lblBatPctVal)     lv_obj_set_style_text_color(lblBatPctVal, c_txt, 0);
  if (lblBatVoltageVal) lv_obj_set_style_text_color(lblBatVoltageVal, c_txt, 0);
  if (lblBatAdcVal)     lv_obj_set_style_text_color(lblBatAdcVal, c_txt, 0);
  if (lblBatK1)         lv_obj_set_style_text_color(lblBatK1, c_dim, 0);
  if (lblBatK2)         lv_obj_set_style_text_color(lblBatK2, c_dim, 0);
  if (lblBatDetails)    lv_obj_set_style_text_color(lblBatDetails, c_dim, 0);

  if (lblWifiPill)      lv_obj_set_style_text_color(lblWifiPill, c_dim, 0);
  if (lblHeapPill)      lv_obj_set_style_text_color(lblHeapPill, c_dim, 0);

  // Wi-Fi Controls styling
  if (lblWifiTitle)     lv_obj_set_style_text_color(lblWifiTitle, dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  if (lblWifiCur)       lv_obj_set_style_text_color(lblWifiCur, c_dim, 0);
  if (lblWifiStatus)    lv_obj_set_style_text_color(lblWifiStatus, c_dim, 0);
  if (taWifiSsid) {
    lv_obj_set_style_bg_color(taWifiSsid, dark ? lv_color_hex(0x0D1117) : lv_color_hex(0xEAEEF2), 0);
    lv_obj_set_style_text_color(taWifiSsid, c_txt, 0);
    lv_obj_set_style_border_color(taWifiSsid, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  }
  if (taWifiPass) {
    lv_obj_set_style_bg_color(taWifiPass, dark ? lv_color_hex(0x0D1117) : lv_color_hex(0xEAEEF2), 0);
    lv_obj_set_style_text_color(taWifiPass, c_txt, 0);
    lv_obj_set_style_border_color(taWifiPass, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  }
  if (btnWifiScan && lblWifiScanBtn) {
    lv_obj_set_style_bg_color(btnWifiScan, dark ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
    lv_obj_set_style_text_color(lblWifiScanBtn, c_txt, 0);
  }
  if (btnWifiShowPass && lblWifiShowPassBtn) {
    lv_obj_set_style_bg_color(btnWifiShowPass, dark ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
    lv_obj_set_style_text_color(lblWifiShowPassBtn, c_txt, 0);
  }
  if (ddWifiSsid) {
    lv_obj_set_style_bg_color(ddWifiSsid, dark ? lv_color_hex(0x0D1117) : lv_color_hex(0xEAEEF2), 0);
    lv_obj_set_style_text_color(ddWifiSsid, c_txt, 0);
    lv_obj_set_style_border_color(ddWifiSsid, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
    lv_obj_t *ddList = lv_dropdown_get_list(ddWifiSsid);
    if (ddList) {
      lv_obj_set_style_bg_color(ddList, dark ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
      lv_obj_set_style_text_color(ddList, c_txt, 0);
      lv_obj_set_style_border_color(ddList, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
    }
  }

  // Keyboard Modal & Typing Preview Bar styling
  if (kbModal) {
    lv_obj_set_style_bg_color(kbModal, dark ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_border_color(kbModal, dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  }
  if (taKbInput) {
    lv_obj_set_style_bg_color(taKbInput, dark ? lv_color_hex(0x0D1117) : lv_color_hex(0xEAEEF2), 0);
    lv_obj_set_style_text_color(taKbInput, c_txt, 0);
    lv_obj_set_style_border_color(taKbInput, dark ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  }
  if (lblKbPrompt) {
    lv_obj_set_style_text_color(lblKbPrompt, dark ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  }
  if (btnKbShowPass && lblKbShowPass) {
    lv_obj_set_style_bg_color(btnKbShowPass, dark ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
    lv_obj_set_style_text_color(lblKbShowPass, c_txt, 0);
  }

  for (int i = 0; i < 4; i++) {
    if (lblRecentTickers[i]) {
      const char *t = lv_label_get_text(lblRecentTickers[i]);
      if (t && strstr(t, "Awaiting inbound probes")) {
        lv_obj_set_style_text_color(lblRecentTickers[i], c_dim, 0);
      }
    }
  }

  esp_lv_adapter_unlock();
}

/*=================== BOOT SPLASH SCREEN =======================*/
static lv_obj_t *splashCont = nullptr;
static lv_obj_t *splashSpinner = nullptr;

void showSplash() {
  if (!esp_lv_adapter_lock(-1)) return;

  // Use a full-screen container over the default active screen (never delete active screen)
  splashCont = lv_obj_create(lv_scr_act());
  lv_obj_set_size(splashCont, 1024, 600);
  lv_obj_align(splashCont, LV_ALIGN_TOP_LEFT, 0, 0);
  lv_obj_clear_flag(splashCont, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(splashCont, lv_color_hex(0x090E14), 0);
  lv_obj_set_style_bg_opa(splashCont, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(splashCont, 0, 0);
  lv_obj_set_style_radius(splashCont, 0, 0);
  lv_obj_set_style_pad_all(splashCont, 0, 0);

  // ── Emblem badge ──
  lv_obj_t *badge = lv_obj_create(splashCont);
  lv_obj_set_size(badge, 68, 68);
  lv_obj_align(badge, LV_ALIGN_CENTER, 0, -70);
  lv_obj_set_style_radius(badge, 34, 0);
  lv_obj_set_style_bg_color(badge, lv_color_hex(0x101D2D), 0);
  lv_obj_set_style_border_color(badge, lv_color_hex(0x58D9F9), 0);
  lv_obj_set_style_border_width(badge, 2, 0);
  lv_obj_clear_flag(badge, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lblIcon = lv_label_create(badge);
  lv_label_set_text(lblIcon, LV_SYMBOL_BELL);
  lv_obj_set_style_text_font(lblIcon, &lv_font_montserrat_28, 0);
  lv_obj_set_style_text_color(lblIcon, lv_color_hex(0x58D9F9), 0);
  lv_obj_center(lblIcon);

  // ── VERA wordmark ──
  lv_obj_t *lblVera = lv_label_create(splashCont);
  lv_label_set_text(lblVera, "V E R A");
  lv_obj_set_style_text_font(lblVera, &lv_font_montserrat_28, 0);
  lv_obj_set_style_text_color(lblVera, lv_color_hex(0x58D9F9), 0);
  lv_obj_align(lblVera, LV_ALIGN_CENTER, 0, -10);

  // ── Subtitle ──
  lv_obj_t *lblSub = lv_label_create(splashCont);
  lv_label_set_text(lblSub, "CYBER DEFENSE NODE");
  lv_obj_set_style_text_font(lblSub, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblSub, lv_color_hex(0x4D6478), 0);
  lv_obj_align(lblSub, LV_ALIGN_CENTER, 0, 22);

  // ── Circular Load Bar (Animated Spinner) ──
  splashSpinner = lv_spinner_create(splashCont, 1000, 60);
  lv_obj_set_size(splashSpinner, 46, 46);
  lv_obj_align(splashSpinner, LV_ALIGN_CENTER, 0, 70);
  lv_obj_set_style_arc_width(splashSpinner, 4, LV_PART_MAIN);
  lv_obj_set_style_arc_color(splashSpinner, lv_color_hex(0x162235), LV_PART_MAIN);
  lv_obj_set_style_arc_width(splashSpinner, 4, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(splashSpinner, lv_color_hex(0x58D9F9), LV_PART_INDICATOR);

  // ── Status label below circular load bar ──
  lv_obj_t *lblLoad = lv_label_create(splashCont);
  lv_label_set_text(lblLoad, "INITIALIZING SYSTEM...");
  lv_obj_set_style_text_font(lblLoad, &lv_font_montserrat_10, 0);
  lv_obj_set_style_text_color(lblLoad, lv_color_hex(0x388BFD), 0);
  lv_obj_align(lblLoad, LV_ALIGN_CENTER, 0, 108);

  // ── Version label (bottom right) ──
  lv_obj_t *lblVer = lv_label_create(splashCont);
  lv_label_set_text(lblVer, "v2.0  Waveshare ESP32-S3-Touch-LCD-7B");
  lv_obj_set_style_text_font(lblVer, &lv_font_montserrat_10, 0);
  lv_obj_set_style_text_color(lblVer, lv_color_hex(0x283A4A), 0);
  lv_obj_align(lblVer, LV_ALIGN_BOTTOM_RIGHT, -14, -10);

  esp_lv_adapter_unlock();

  // Enable backlight at 15% so splash is visible during hardware init
  IO_EXTENSION_Pwm_Output(15);
  wavesahre_rgb_lcd_bl_on();

  // Hold splash for 2.0 s (LVGL timer keeps running so circular load bar rotates)
  delay(2000);

  // Turn backlight off before building real UI to avoid white flash
  IO_EXTENSION_Pwm_Output(0);

  // Tear down splash container cleanly
  if (esp_lv_adapter_lock(-1)) {
    if (splashCont) {
      lv_obj_del(splashCont);
      splashCont = nullptr;
      splashSpinner = nullptr;
    }
    esp_lv_adapter_unlock();
  }
}

/* Create the Complete 1024x600 GUI */
void createUI() {
  if (!esp_lv_adapter_lock(-1)) return;

  uiCardCount = 0;
  metricCardCount = 0;
  scr = lv_scr_act();
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0B0F14), 0);

  /* ---- 1. HEADER BAR (1024 x 46) ---- */
  hdr = lv_obj_create(scr);
  lv_obj_set_size(hdr, 1024, 46);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_pad_hor(hdr, 14, 0);
  lv_obj_set_style_pad_ver(hdr, 6, 0);
  lv_obj_set_style_bg_color(hdr, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xE1E4E8), 0);

  // Title (Left: X = 0)
  lblTitle = lv_label_create(hdr);
  lv_label_set_text(lblTitle, "VERA");
  lv_obj_set_style_text_font(lblTitle, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(lblTitle, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  lv_obj_align(lblTitle, LV_ALIGN_LEFT_MID, 0, 0);

  // Clock (Left: X = 65)
  lblClock = lv_label_create(hdr);
  lv_label_set_text(lblClock, "00:00:00");
  lv_obj_set_style_text_font(lblClock, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(lblClock, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblClock, LV_ALIGN_LEFT_MID, 65, 0);

  // Theme Toggle Button (Left: X = 160)
  btnTheme = lv_btn_create(hdr);
  lv_obj_set_size(btnTheme, 88, 30);
  lv_obj_align(btnTheme, LV_ALIGN_LEFT_MID, 160, 0);
  lv_obj_set_style_radius(btnTheme, 6, 0);
  lv_obj_set_style_border_width(btnTheme, 1, 0);
  lv_obj_set_style_border_color(btnTheme, isDarkMode ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  lv_obj_set_style_bg_color(btnTheme, isDarkMode ? lv_color_hex(0x21262D) : lv_color_hex(0xD0D7DE), 0);
  lv_obj_add_event_cb(btnTheme, onThemeToggleClicked, LV_EVENT_CLICKED, NULL);

  lblThemeBtn = lv_label_create(btnTheme);
  lv_label_set_text(lblThemeBtn, isDarkMode ? "☀️ LIGHT" : "🌙 DARK");
  lv_obj_set_style_text_font(lblThemeBtn, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblThemeBtn, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_center(lblThemeBtn);

  // Battery Pill (Left: X = 265)
  lblBatteryPill = lv_label_create(hdr);
  lv_label_set_text(lblBatteryPill, "⚡ BAT --");
  lv_obj_set_style_text_font(lblBatteryPill, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblBatteryPill, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  lv_obj_align(lblBatteryPill, LV_ALIGN_LEFT_MID, 265, 0);

  // SD Badge (Left: X = 435)
  lblSdBadge = lv_label_create(hdr);
  lv_label_set_text(lblSdBadge, "NO SD");
  lv_obj_set_style_text_font(lblSdBadge, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblSdBadge, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xCF222E), 0);
  lv_obj_align(lblSdBadge, LV_ALIGN_LEFT_MID, 435, 0);

  // WiFi Pill (Right: offset -80)
  lblWifiPill = lv_label_create(hdr);
  lv_label_set_text(lblWifiPill, "Connecting...");
  lv_obj_set_style_text_font(lblWifiPill, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblWifiPill, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblWifiPill, LV_ALIGN_RIGHT_MID, -80, 0);

  // Free Heap (Right: offset 0)
  lblHeapPill = lv_label_create(hdr);
  lv_label_set_text(lblHeapPill, "--k free");
  lv_obj_set_style_text_font(lblHeapPill, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblHeapPill, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblHeapPill, LV_ALIGN_RIGHT_MID, 0, 0);

  /* ---- 2. TABVIEW (1024 x 554) ---- */
  tabview = lv_tabview_create(scr, LV_DIR_TOP, 42);
  lv_obj_set_size(tabview, 1024, 554);
  lv_obj_align(tabview, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_bg_color(tabview, isDarkMode ? lv_color_hex(0x0B0F14) : lv_color_hex(0xF0F2F5), 0);

  lv_obj_t *tab_btns = lv_tabview_get_tab_btns(tabview);
  if (tab_btns) {
    lv_obj_set_style_bg_color(tab_btns, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xE1E4E8), 0);
    lv_obj_set_style_text_color(tab_btns, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  }

  lv_obj_t *tOverview = lv_tabview_add_tab(tabview, "OVERVIEW");
  lv_obj_t *tLogs     = lv_tabview_add_tab(tabview, "THREAT LOG");
  lv_obj_t *tIps      = lv_tabview_add_tab(tabview, "ATTACKERS");
  lv_obj_t *tLoot     = lv_tabview_add_tab(tabview, "CAPTURED LOOT");
  lv_obj_t *tSettings = lv_tabview_add_tab(tabview, "SYSTEM");

  /* ========================================================
     TAB 1: OVERVIEW (SOC DASHBOARD)
     ======================================================== */
  lv_obj_set_style_pad_all(tOverview, 10, 0);

  // Row 1: Protocol Stat Cards
  lv_obj_t *row1 = lv_obj_create(tOverview);
  lv_obj_set_size(row1, 996, 110);
  lv_obj_align(row1, LV_ALIGN_TOP_MID, 0, 0);
  lv_obj_set_flex_flow(row1, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row1, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_bg_opa(row1, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(row1, 0, 0);
  lv_obj_set_style_pad_all(row1, 0, 0);

  metricCardCount = 0;
  createMetricCard(row1, "TELNET (PORT 23)", 0x3FB950, 0x0F5323, &lblValTelnet);
  createMetricCard(row1, "SSH (PORT 22)",    0x39C5CF, 0x0550AE, &lblValSsh);
  createMetricCard(row1, "FTP (PORT 21)",    0xD29922, 0x8C5303, &lblValFtp);
  createMetricCard(row1, "HTTP (PORT 80)",   0xF0883E, 0xA40E26, &lblValHttp);
  createMetricCard(row1, "PING (ICMP)",      0xDB61A2, 0x5C2B97, &lblValPing);

  // Row 2: Secondary Threat Metric Cards
  lv_obj_t *row2 = lv_obj_create(tOverview);
  lv_obj_set_size(row2, 996, 110);
  lv_obj_align(row2, LV_ALIGN_TOP_MID, 0, 118);
  lv_obj_set_flex_flow(row2, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row2, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_bg_opa(row2, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(row2, 0, 0);
  lv_obj_set_style_pad_all(row2, 0, 0);

  createMetricCard(row2, "TOTAL PROBES",   0x58A6FF, 0x0550AE, &lblValTotal);
  createMetricCard(row2, "UNIQUE HOSTS",   0x7EE787, 0x0F5323, &lblValIps);
  createMetricCard(row2, "CREDS HARVEST",  0xF85149, 0xA40E26, &lblValCreds);
  createMetricCard(row2, "SHELL PAYLOADS", 0xF85149, 0xA40E26, &lblValPayloads);
  createMetricCard(row2, "PORT SCANNERS",  0xBC8CFF, 0x5C2B97, &lblValScans);

  // Row 3: Service Distribution & Live Activity Ticker
  lv_obj_t *cardDist = lv_obj_create(tOverview);
  lv_obj_set_size(cardDist, 488, 230);
  lv_obj_align(cardDist, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_obj_set_style_radius(cardDist, 8, 0);
  lv_obj_set_style_pad_all(cardDist, 10, 0);
  lv_obj_set_style_bg_color(cardDist, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_border_color(cardDist, isDarkMode ? lv_color_hex(0x30363D) : lv_color_hex(0x8C959F), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = cardDist;

  lblDistT = lv_label_create(cardDist);
  lv_label_set_text(lblDistT, "SERVICE ATTACK DISTRIBUTION");
  lv_obj_set_style_text_font(lblDistT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblDistT, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);

  // Distribution Bars
  distBarCount = 0;
  auto makeBar = [&](const char *name, uint32_t darkCol, uint32_t lightCol, int y, lv_obj_t **b, lv_obj_t **l) {
    uint32_t col = isDarkMode ? darkCol : lightCol;
    lv_obj_t *t = lv_label_create(cardDist);
    lv_label_set_text(t, name);
    lv_obj_set_style_text_font(t, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(t, lv_color_hex(col), 0);
    lv_obj_align(t, LV_ALIGN_TOP_LEFT, 0, y);

    *b = lv_bar_create(cardDist);
    lv_obj_set_size(*b, 340, 14);
    lv_obj_align(*b, LV_ALIGN_TOP_LEFT, 64, y);
    lv_obj_set_style_radius(*b, 4, 0);
    lv_obj_set_style_radius(*b, 3, LV_PART_INDICATOR);
    lv_obj_set_style_border_width(*b, 2, 0);
    lv_obj_set_style_border_color(*b, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x57606A), 0);
    lv_obj_set_style_pad_all(*b, 1, 0);
    lv_obj_set_style_bg_color(*b, isDarkMode ? lv_color_hex(0x21262D) : lv_color_hex(0xEAEEF2), 0);
    lv_obj_set_style_bg_color(*b, lv_color_hex(col), LV_PART_INDICATOR);
    lv_bar_set_range(*b, 0, 100);

    *l = lv_label_create(cardDist);
    lv_label_set_text(*l, "0");
    lv_obj_set_style_text_font(*l, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(*l, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
    lv_obj_align(*l, LV_ALIGN_TOP_RIGHT, 0, y);

    if (distBarCount < 5) {
      distBars[distBarCount++] = {*b, t, *l, darkCol, lightCol};
    }
  };

  makeBar("TELNET", 0x3FB950, 0x0F5323, 30,  &barTelnet, &lblBarTelnet);
  makeBar("SSH",    0x39C5CF, 0x0550AE, 65,  &barSsh,    &lblBarSsh);
  makeBar("FTP",    0xD29922, 0x8C5303, 100, &barFtp,    &lblBarFtp);
  makeBar("HTTP",   0xF0883E, 0xA40E26, 135, &barHttp,   &lblBarHttp);
  makeBar("PING",   0xDB61A2, 0x5C2B97, 170, &barPing,   &lblBarPing);

  // Live Activity Ticker Box
  lv_obj_t *cardTicker = lv_obj_create(tOverview);
  lv_obj_set_size(cardTicker, 488, 230);
  lv_obj_align(cardTicker, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
  lv_obj_set_style_radius(cardTicker, 8, 0);
  lv_obj_set_style_pad_all(cardTicker, 10, 0);
  lv_obj_set_style_bg_color(cardTicker, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_border_color(cardTicker, isDarkMode ? lv_color_hex(0x30363D) : lv_color_hex(0xD0D7DE), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = cardTicker;

  lblTickT = lv_label_create(cardTicker);
  lv_label_set_text(lblTickT, "LATEST THREAT FEED");
  lv_obj_set_style_text_font(lblTickT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblTickT, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xCF222E), 0);

  for (int i = 0; i < 4; i++) {
    lblRecentTickers[i] = lv_label_create(cardTicker);
    lv_label_set_text(lblRecentTickers[i], "[--:--:--] System Armed. Awaiting inbound probes...");
    lv_obj_set_style_text_font(lblRecentTickers[i], &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(lblRecentTickers[i], lv_color_hex(0x8B949E), 0);
    lv_obj_align(lblRecentTickers[i], LV_ALIGN_TOP_LEFT, 0, 30 + i * 44);
  }

  /* ========================================================
     TAB 2: THREAT LOG (INTERACTIVE CONSOLE)
     ======================================================== */
  lv_obj_set_style_pad_all(tLogs, 8, 0);

  tableLog = lv_table_create(tLogs);
  lv_obj_set_size(tableLog, 996, 450);
  lv_obj_align(tableLog, LV_ALIGN_TOP_MID, 0, 0);
  lv_table_set_col_width(tableLog, 0, 95);  // Time
  lv_table_set_col_width(tableLog, 1, 85);  // Service
  lv_table_set_col_width(tableLog, 2, 280); // Source IP & MAC
  lv_table_set_col_width(tableLog, 3, 520); // Detail
  lv_table_set_cell_value(tableLog, 0, 0, "TIME");
  lv_table_set_cell_value(tableLog, 0, 1, "SERVICE");
  lv_table_set_cell_value(tableLog, 0, 2, "SOURCE IP & MAC");
  lv_table_set_cell_value(tableLog, 0, 3, "EVENT DETAIL");
  lv_obj_add_event_cb(tableLog, onLogTableClicked, LV_EVENT_VALUE_CHANGED, NULL);

  /* ========================================================
     TAB 3: ATTACKING HOSTS
     ======================================================== */
  lv_obj_set_style_pad_all(tIps, 8, 0);

  tableIps = lv_table_create(tIps);
  lv_obj_set_size(tableIps, 996, 450);
  lv_obj_align(tableIps, LV_ALIGN_TOP_MID, 0, 0);
  lv_table_set_col_width(tableIps, 0, 200); // IP
  lv_table_set_col_width(tableIps, 1, 210); // MAC Address
  lv_table_set_col_width(tableIps, 2, 330); // Services touched
  lv_table_set_col_width(tableIps, 3, 230); // Threat Level
  lv_table_set_cell_value(tableIps, 0, 0, "ATTACKER IP");
  lv_table_set_cell_value(tableIps, 0, 1, "MAC ADDRESS");
  lv_table_set_cell_value(tableIps, 0, 2, "TOUCHED SERVICES");
  lv_table_set_cell_value(tableIps, 0, 3, "THREAT LEVEL");

  /* ========================================================
     TAB 4: CAPTURED LOOT
     ======================================================== */
  lv_obj_set_style_pad_all(tLoot, 8, 0);

  lv_obj_t *boxCreds = lv_obj_create(tLoot);
  lv_obj_set_size(boxCreds, 488, 450);
  lv_obj_align(boxCreds, LV_ALIGN_LEFT_MID, 0, 0);
  lv_obj_set_style_pad_all(boxCreds, 6, 0);
  lv_obj_set_style_bg_color(boxCreds, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_border_color(boxCreds, isDarkMode ? lv_color_hex(0x30363D) : lv_color_hex(0xD0D7DE), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = boxCreds;

  lblCrT = lv_label_create(boxCreds);
  lv_label_set_text(lblCrT, "CAPTURED CREDENTIALS");
  lv_obj_set_style_text_font(lblCrT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblCrT, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xA40E26), 0);

  tableCreds = lv_table_create(boxCreds);
  lv_obj_set_size(tableCreds, 470, 390);
  lv_obj_align(tableCreds, LV_ALIGN_TOP_MID, 0, 24);
  lv_table_set_col_width(tableCreds, 0, 70);  // Svc
  lv_table_set_col_width(tableCreds, 1, 120); // IP
  lv_table_set_col_width(tableCreds, 2, 130); // User
  lv_table_set_col_width(tableCreds, 3, 130); // Password
  lv_table_set_cell_value(tableCreds, 0, 0, "SVC");
  lv_table_set_cell_value(tableCreds, 0, 1, "SOURCE");
  lv_table_set_cell_value(tableCreds, 0, 2, "USERNAME");
  lv_table_set_cell_value(tableCreds, 0, 3, "PASSWORD");

  lv_obj_t *boxPayloads = lv_obj_create(tLoot);
  lv_obj_set_size(boxPayloads, 488, 450);
  lv_obj_align(boxPayloads, LV_ALIGN_RIGHT_MID, 0, 0);
  lv_obj_set_style_pad_all(boxPayloads, 6, 0);
  lv_obj_set_style_bg_color(boxPayloads, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_border_color(boxPayloads, isDarkMode ? lv_color_hex(0x30363D) : lv_color_hex(0xD0D7DE), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = boxPayloads;

  lblPlT = lv_label_create(boxPayloads);
  lv_label_set_text(lblPlT, "EXPLOIT COMMANDS & PAYLOAD URLS");
  lv_obj_set_style_text_font(lblPlT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblPlT, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xA40E26), 0);

  tablePayloads = lv_table_create(boxPayloads);
  lv_obj_set_size(tablePayloads, 470, 390);
  lv_obj_align(tablePayloads, LV_ALIGN_TOP_MID, 0, 24);
  lv_table_set_col_width(tablePayloads, 0, 70);  // Svc
  lv_table_set_col_width(tablePayloads, 1, 120); // IP
  lv_table_set_col_width(tablePayloads, 2, 260); // Command
  lv_table_set_cell_value(tablePayloads, 0, 0, "SVC");
  lv_table_set_cell_value(tablePayloads, 0, 1, "SOURCE");
  lv_table_set_cell_value(tablePayloads, 0, 2, "PAYLOAD COMMAND");

  /* ========================================================
     TAB 5: SYSTEM & HARDWARE CONTROL
     ======================================================== */
  lv_obj_set_style_pad_all(tSettings, 10, 0);

  // Left Card: Display, Theme & Node Controls (485 x 475)
  lv_obj_t *cardSys = lv_obj_create(tSettings);
  lv_obj_set_size(cardSys, 488, 475);
  lv_obj_align(cardSys, LV_ALIGN_TOP_LEFT, 0, 0);
  lv_obj_set_style_radius(cardSys, 8, 0);
  lv_obj_set_style_pad_all(cardSys, 12, 0);
  lv_obj_set_style_border_width(cardSys, 2, 0);
  lv_obj_set_style_border_color(cardSys, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  lv_obj_set_style_bg_color(cardSys, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = cardSys;

  lblSysT = lv_label_create(cardSys);
  lv_label_set_text(lblSysT, "DISPLAY & SYSTEM CONTROLS");
  lv_obj_set_style_text_font(lblSysT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblSysT, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  lv_obj_align(lblSysT, LV_ALIGN_TOP_LEFT, 0, 0);

  // Backlight Slider
  lblBlt = lv_label_create(cardSys);
  lv_label_set_text(lblBlt, "LCD Backlight (PWM via CH32V003):");
  lv_obj_set_style_text_font(lblBlt, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblBlt, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblBlt, LV_ALIGN_TOP_LEFT, 0, 24);

  sliderBrightness = lv_slider_create(cardSys);
  lv_obj_set_size(sliderBrightness, 360, 18);
  lv_obj_align(sliderBrightness, LV_ALIGN_TOP_LEFT, 0, 48);
  lv_slider_set_range(sliderBrightness, 10, 100);
  lv_slider_set_value(sliderBrightness, currentBrightness, LV_ANIM_OFF);
  lv_obj_add_event_cb(sliderBrightness, onBrightnessSliderChanged, LV_EVENT_VALUE_CHANGED, NULL);

  lblBrightnessVal = lv_label_create(cardSys);
  char bBuf[16];
  snprintf(bBuf, sizeof(bBuf), "%d%%", currentBrightness);
  lv_label_set_text(lblBrightnessVal, bBuf);
  lv_obj_set_style_text_font(lblBrightnessVal, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblBrightnessVal, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblBrightnessVal, LV_ALIGN_TOP_LEFT, 380, 48);

  // Theme Settings Section
  lblThemeSec = lv_label_create(cardSys);
  lv_label_set_text(lblThemeSec, "UI Mode Theme Selection:");
  lv_obj_set_style_text_font(lblThemeSec, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblThemeSec, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblThemeSec, LV_ALIGN_TOP_LEFT, 0, 84);

  lblThemeModeInfo = lv_label_create(cardSys);
  lv_label_set_text(lblThemeModeInfo, isDarkMode ? "Current Mode: DARK (Cyber SOC)" : "Current Mode: LIGHT (Daylight)");
  lv_obj_set_style_text_font(lblThemeModeInfo, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblThemeModeInfo, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblThemeModeInfo, LV_ALIGN_TOP_LEFT, 0, 106);

  btnThemeSettings = lv_btn_create(cardSys);
  lv_obj_set_size(btnThemeSettings, 220, 34);
  lv_obj_align(btnThemeSettings, LV_ALIGN_TOP_LEFT, 0, 132);
  lv_obj_set_style_radius(btnThemeSettings, 6, 0);
  lv_obj_add_event_cb(btnThemeSettings, onThemeToggleClicked, LV_EVENT_CLICKED, NULL);

  lblThemeSettingsBtn = lv_label_create(btnThemeSettings);
  lv_label_set_text(lblThemeSettingsBtn, isDarkMode ? "Switch to Light UI" : "Switch to Dark UI");
  lv_obj_set_style_text_font(lblThemeSettingsBtn, &lv_font_montserrat_12, 0);
  lv_obj_center(lblThemeSettingsBtn);

  // Storage and Node info
  lblSdInfo = lv_label_create(cardSys);
  lv_label_set_text(lblSdInfo, "STORAGE: MicroSD (SDMMC 1-bit mode)\n"
                               "PINS: CLK=12, CMD=11, D0=13\n"
                               "LOGS: /vera.log | STATE: /state.bin\n\n"
                               "WEB ADMIN URL: http://<ip>:8080/?key=" ADMIN_KEY);
  lv_obj_set_style_text_font(lblSdInfo, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblSdInfo, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblSdInfo, LV_ALIGN_TOP_LEFT, 0, 186);

  // Clear data button
  lv_obj_t *btnClear = lv_btn_create(cardSys);
  lv_obj_set_size(btnClear, 220, 38);
  lv_obj_align(btnClear, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_obj_set_style_bg_color(btnClear, lv_color_hex(0xDA3633), 0);
  lv_obj_add_event_cb(btnClear, onClearBtnClicked, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lblClr = lv_label_create(btnClear);
  lv_label_set_text(lblClr, "Wipe Logs & Reset State");
  lv_obj_set_style_text_font(lblClr, &lv_font_montserrat_12, 0);
  lv_obj_center(lblClr);

  // Right Top Card: Power & Battery Subsystem (488 x 205)
  lv_obj_t *cardBat = lv_obj_create(tSettings);
  lv_obj_set_size(cardBat, 488, 205);
  lv_obj_align(cardBat, LV_ALIGN_TOP_RIGHT, 0, 0);
  lv_obj_set_style_radius(cardBat, 8, 0);
  lv_obj_set_style_pad_all(cardBat, 10, 0);
  lv_obj_set_style_border_width(cardBat, 2, 0);
  lv_obj_set_style_border_color(cardBat, isDarkMode ? lv_color_hex(0x3FB950) : lv_color_hex(0x0F5323), 0);
  lv_obj_set_style_bg_color(cardBat, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = cardBat;

  lblBatT = lv_label_create(cardBat);
  lv_label_set_text(lblBatT, "POWER & BATTERY SUBSYSTEM (CS8501)");
  lv_obj_set_style_text_font(lblBatT, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblBatT, isDarkMode ? lv_color_hex(0x3FB950) : lv_color_hex(0x0F5323), 0);
  lv_obj_align(lblBatT, LV_ALIGN_TOP_LEFT, 0, 0);

  // Battery Level Bar
  barBattery = lv_bar_create(cardBat);
  lv_obj_set_size(barBattery, 450, 18);
  lv_obj_align(barBattery, LV_ALIGN_TOP_LEFT, 0, 22);
  lv_obj_set_style_radius(barBattery, 4, 0);
  lv_obj_set_style_radius(barBattery, 3, LV_PART_INDICATOR);
  lv_obj_set_style_border_width(barBattery, 2, 0);
  lv_obj_set_style_border_color(barBattery, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x57606A), 0);
  lv_obj_set_style_pad_all(barBattery, 1, 0);
  lv_obj_set_style_bg_color(barBattery, isDarkMode ? lv_color_hex(0x21262D) : lv_color_hex(0xEAEEF2), 0);
  lv_obj_set_style_bg_color(barBattery, isDarkMode ? lv_color_hex(0x3FB950) : lv_color_hex(0x0F5323), LV_PART_INDICATOR);
  lv_bar_set_range(barBattery, 0, 100);
  lv_bar_set_value(barBattery, 0, LV_ANIM_OFF);

  // Large Battery readout
  lblBatPctVal = lv_label_create(cardBat);
  lv_label_set_text(lblBatPctVal, "--%");
  lv_obj_set_style_text_font(lblBatPctVal, &lv_font_montserrat_28, 0);
  lv_obj_set_style_text_color(lblBatPctVal, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblBatPctVal, LV_ALIGN_TOP_LEFT, 0, 44);

  lblBatStatusVal = lv_label_create(cardBat);
  lv_label_set_text(lblBatStatusVal, "Reading battery telemetry...");
  lv_obj_set_style_text_font(lblBatStatusVal, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblBatStatusVal, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  lv_obj_align(lblBatStatusVal, LV_ALIGN_TOP_LEFT, 0, 76);

  // Metrics Table / Key-Value list
  auto makeBatRow = [&](const char *label, const char *initVal, int y, lv_obj_t **outVal, lv_obj_t **outKey) {
    lv_obj_t *lblK = lv_label_create(cardBat);
    lv_label_set_text(lblK, label);
    lv_obj_set_style_text_font(lblK, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(lblK, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
    lv_obj_align(lblK, LV_ALIGN_TOP_LEFT, 0, y);
    if (outKey) *outKey = lblK;

    lv_obj_t *lblV = lv_label_create(cardBat);
    lv_label_set_text(lblV, initVal);
    lv_obj_set_style_text_font(lblV, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(lblV, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
    lv_obj_align(lblV, LV_ALIGN_TOP_LEFT, 150, y);
    if (outVal) *outVal = lblV;
  };

  makeBatRow("Battery Voltage:", "-- V", 100, &lblBatVoltageVal, &lblBatK1);
  makeBatRow("Expander ADC Raw:", "-- / 1023", 122, &lblBatAdcVal, &lblBatK2);

  lblBatDetails = lv_label_create(cardBat);
  lv_label_set_text(lblBatDetails,
    "CS8501 580mA · Single-Cell 3.7V Li-ion (PH2.0) · CH32V003 3:1 ADC"
  );
  lv_obj_set_style_text_font(lblBatDetails, &lv_font_montserrat_10, 0);
  lv_obj_set_style_text_color(lblBatDetails, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblBatDetails, LV_ALIGN_TOP_LEFT, 0, 150);

  // Right Bottom Card: Wi-Fi Configuration (488 x 255)
  cardWifi = lv_obj_create(tSettings);
  lv_obj_set_size(cardWifi, 488, 255);
  lv_obj_align(cardWifi, LV_ALIGN_TOP_RIGHT, 0, 220);
  lv_obj_set_style_radius(cardWifi, 8, 0);
  lv_obj_set_style_pad_all(cardWifi, 10, 0);
  lv_obj_set_style_border_width(cardWifi, 2, 0);
  lv_obj_set_style_border_color(cardWifi, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  lv_obj_set_style_bg_color(cardWifi, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  if (uiCardCount < 24) uiCards[uiCardCount++] = cardWifi;

  lblWifiTitle = lv_label_create(cardWifi);
  lv_label_set_text(lblWifiTitle, "WI-FI CONFIGURATION & CONNECT");
  lv_obj_set_style_text_font(lblWifiTitle, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblWifiTitle, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0550AE), 0);
  lv_obj_align(lblWifiTitle, LV_ALIGN_TOP_LEFT, 0, 0);

  lblWifiCur = lv_label_create(cardWifi);
  lv_label_set_text(lblWifiCur, "Status: Connecting...");
  lv_obj_set_style_text_font(lblWifiCur, &lv_font_montserrat_10, 0);
  lv_obj_set_style_text_color(lblWifiCur, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblWifiCur, LV_ALIGN_TOP_LEFT, 0, 20);

  // SSID Label & Textarea & Scan Button
  lv_obj_t *lblSsidTag = lv_label_create(cardWifi);
  lv_label_set_text(lblSsidTag, "SSID:");
  lv_obj_set_style_text_font(lblSsidTag, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblSsidTag, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblSsidTag, LV_ALIGN_TOP_LEFT, 0, 48);

  taWifiSsid = lv_textarea_create(cardWifi);
  lv_obj_set_size(taWifiSsid, 270, 32);
  lv_obj_align(taWifiSsid, LV_ALIGN_TOP_LEFT, 65, 42);
  lv_textarea_set_one_line(taWifiSsid, true);
  lv_textarea_set_placeholder_text(taWifiSsid, "Network SSID");
  lv_textarea_set_text(taWifiSsid, curWifiSsid);
  lv_obj_add_event_cb(taWifiSsid, onWifiInputFocused, LV_EVENT_FOCUSED, NULL);
  lv_obj_add_event_cb(taWifiSsid, onWifiInputFocused, LV_EVENT_CLICKED, NULL);

  btnWifiScan = lv_btn_create(cardWifi);
  lv_obj_set_size(btnWifiScan, 110, 32);
  lv_obj_align(btnWifiScan, LV_ALIGN_TOP_LEFT, 345, 42);
  lv_obj_set_style_radius(btnWifiScan, 6, 0);
  lv_obj_add_event_cb(btnWifiScan, onWifiScanClicked, LV_EVENT_CLICKED, NULL);

  lblWifiScanBtn = lv_label_create(btnWifiScan);
  lv_label_set_text(lblWifiScanBtn, "🔍 Scan APs");
  lv_obj_set_style_text_font(lblWifiScanBtn, &lv_font_montserrat_10, 0);
  lv_obj_center(lblWifiScanBtn);

  // APs Dropdown
  lv_obj_t *lblApTag = lv_label_create(cardWifi);
  lv_label_set_text(lblApTag, "APs:");
  lv_obj_set_style_text_font(lblApTag, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblApTag, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblApTag, LV_ALIGN_TOP_LEFT, 0, 86);

  ddWifiSsid = lv_dropdown_create(cardWifi);
  lv_obj_set_size(ddWifiSsid, 390, 32);
  lv_obj_align(ddWifiSsid, LV_ALIGN_TOP_LEFT, 65, 80);
  lv_dropdown_set_options(ddWifiSsid, "-- Tap 'Scan APs' to discover networks --");
  lv_obj_add_event_cb(ddWifiSsid, onWifiDropdownChanged, LV_EVENT_VALUE_CHANGED, NULL);

  // Password Label & Textarea & Show button
  lv_obj_t *lblPassTag = lv_label_create(cardWifi);
  lv_label_set_text(lblPassTag, "Pass:");
  lv_obj_set_style_text_font(lblPassTag, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblPassTag, isDarkMode ? lv_color_hex(0xF0F6FC) : lv_color_hex(0x1F2328), 0);
  lv_obj_align(lblPassTag, LV_ALIGN_TOP_LEFT, 0, 124);

  taWifiPass = lv_textarea_create(cardWifi);
  lv_obj_set_size(taWifiPass, 310, 32);
  lv_obj_align(taWifiPass, LV_ALIGN_TOP_LEFT, 65, 118);
  lv_textarea_set_one_line(taWifiPass, true);
  lv_textarea_set_password_mode(taWifiPass, true);
  lv_textarea_set_placeholder_text(taWifiPass, "Password");
  lv_textarea_set_text(taWifiPass, curWifiPass);
  lv_obj_add_event_cb(taWifiPass, onWifiInputFocused, LV_EVENT_FOCUSED, NULL);
  lv_obj_add_event_cb(taWifiPass, onWifiInputFocused, LV_EVENT_CLICKED, NULL);

  btnWifiShowPass = lv_btn_create(cardWifi);
  lv_obj_set_size(btnWifiShowPass, 70, 32);
  lv_obj_align(btnWifiShowPass, LV_ALIGN_TOP_LEFT, 385, 118);
  lv_obj_set_style_radius(btnWifiShowPass, 6, 0);
  lv_obj_add_event_cb(btnWifiShowPass, onWifiShowPassClicked, LV_EVENT_CLICKED, NULL);

  lblWifiShowPassBtn = lv_label_create(btnWifiShowPass);
  lv_label_set_text(lblWifiShowPassBtn, "Show");
  lv_obj_set_style_text_font(lblWifiShowPassBtn, &lv_font_montserrat_10, 0);
  lv_obj_center(lblWifiShowPassBtn);

  // Connect Button
  btnWifiConnect = lv_btn_create(cardWifi);
  lv_obj_set_size(btnWifiConnect, 160, 34);
  lv_obj_align(btnWifiConnect, LV_ALIGN_TOP_LEFT, 65, 156);
  lv_obj_set_style_radius(btnWifiConnect, 6, 0);
  lv_obj_set_style_bg_color(btnWifiConnect, lv_color_hex(0x238636), 0);
  lv_obj_add_event_cb(btnWifiConnect, onWifiConnectClicked, LV_EVENT_CLICKED, NULL);

  lblWifiConnBtn = lv_label_create(btnWifiConnect);
  lv_label_set_text(lblWifiConnBtn, "Connect Wi-Fi");
  lv_obj_set_style_text_font(lblWifiConnBtn, &lv_font_montserrat_12, 0);
  lv_obj_center(lblWifiConnBtn);

  // Status Message
  lblWifiStatus = lv_label_create(cardWifi);
  lv_label_set_text(lblWifiStatus, "Ready. Select network and enter password.");
  lv_obj_set_style_text_font(lblWifiStatus, &lv_font_montserrat_10, 0);
  lv_obj_set_style_text_color(lblWifiStatus, isDarkMode ? lv_color_hex(0x8B949E) : lv_color_hex(0x24292F), 0);
  lv_obj_align(lblWifiStatus, LV_ALIGN_TOP_LEFT, 0, 202);

  /* ---- 5. ON-SCREEN KEYBOARD MODAL & PREVIEW DIALOG ---- */
  kbModal = lv_obj_create(scr);
  lv_obj_set_size(kbModal, 1010, 288);
  lv_obj_align(kbModal, LV_ALIGN_BOTTOM_MID, 0, -4);
  lv_obj_clear_flag(kbModal, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_radius(kbModal, 8, 0);
  lv_obj_set_style_pad_all(kbModal, 6, 0);
  lv_obj_set_style_border_width(kbModal, 2, 0);
  lv_obj_set_style_border_color(kbModal, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  lv_obj_set_style_bg_color(kbModal, isDarkMode ? lv_color_hex(0x161B22) : lv_color_hex(0xFFFFFF), 0);
  lv_obj_add_flag(kbModal, LV_OBJ_FLAG_HIDDEN);

  // Top Live Typing / Preview Header Bar
  lblKbPrompt = lv_label_create(kbModal);
  lv_label_set_text(lblKbPrompt, "INPUT:");
  lv_obj_set_style_text_font(lblKbPrompt, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_color(lblKbPrompt, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
  lv_obj_align(lblKbPrompt, LV_ALIGN_TOP_LEFT, 6, 10);

  taKbInput = lv_textarea_create(kbModal);
  lv_obj_set_size(taKbInput, 610, 36);
  lv_obj_align(taKbInput, LV_ALIGN_TOP_LEFT, 85, 2);
  lv_textarea_set_one_line(taKbInput, true);
  lv_obj_set_style_text_font(taKbInput, &lv_font_montserrat_14, 0);
  lv_obj_set_style_radius(taKbInput, 6, 0);

  btnKbShowPass = lv_btn_create(kbModal);
  lv_obj_set_size(btnKbShowPass, 75, 36);
  lv_obj_align(btnKbShowPass, LV_ALIGN_TOP_LEFT, 705, 2);
  lv_obj_set_style_radius(btnKbShowPass, 6, 0);
  lv_obj_add_event_cb(btnKbShowPass, onKbTogglePassClicked, LV_EVENT_CLICKED, NULL);

  lblKbShowPass = lv_label_create(btnKbShowPass);
  lv_label_set_text(lblKbShowPass, "Show");
  lv_obj_set_style_text_font(lblKbShowPass, &lv_font_montserrat_12, 0);
  lv_obj_center(lblKbShowPass);

  btnKbDone = lv_btn_create(kbModal);
  lv_obj_set_size(btnKbDone, 100, 36);
  lv_obj_align(btnKbDone, LV_ALIGN_TOP_LEFT, 790, 2);
  lv_obj_set_style_radius(btnKbDone, 6, 0);
  lv_obj_set_style_bg_color(btnKbDone, lv_color_hex(0x238636), 0);
  lv_obj_add_event_cb(btnKbDone, onKbDoneClicked, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lblKbDone = lv_label_create(btnKbDone);
  lv_label_set_text(lblKbDone, "✔ Done");
  lv_obj_set_style_text_font(lblKbDone, &lv_font_montserrat_12, 0);
  lv_obj_center(lblKbDone);

  btnKbCancel = lv_btn_create(kbModal);
  lv_obj_set_size(btnKbCancel, 90, 36);
  lv_obj_align(btnKbCancel, LV_ALIGN_TOP_LEFT, 900, 2);
  lv_obj_set_style_radius(btnKbCancel, 6, 0);
  lv_obj_set_style_bg_color(btnKbCancel, lv_color_hex(0xDA3633), 0);
  lv_obj_add_event_cb(btnKbCancel, onKbCancelClicked, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lblKbCancel = lv_label_create(btnKbCancel);
  lv_label_set_text(lblKbCancel, "✖ Close");
  lv_obj_set_style_text_font(lblKbCancel, &lv_font_montserrat_12, 0);
  lv_obj_center(lblKbCancel);

  // Capacitive Keyboard attached directly to the preview textarea
  kbWifi = lv_keyboard_create(kbModal);
  lv_obj_set_size(kbWifi, 994, 232);
  lv_obj_align(kbWifi, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_keyboard_set_textarea(kbWifi, taKbInput);
  lv_obj_add_event_cb(kbWifi, onWifiKeyboardAction, LV_EVENT_ALL, NULL);

  // Apply complete theme while mutex is still held to prevent any unstyled white flash
  applyTheme(isDarkMode);

  esp_lv_adapter_unlock();
}

/* Update dashboard numbers and progress bars */
void updateDashboardMetrics() {
  if (!esp_lv_adapter_lock(100)) return;

  char buf[16];
  snprintf(buf, sizeof(buf), "%u", st.telnet);   if (lblValTelnet) lv_label_set_text(lblValTelnet, buf);
  snprintf(buf, sizeof(buf), "%u", st.ssh);      if (lblValSsh)    lv_label_set_text(lblValSsh, buf);
  snprintf(buf, sizeof(buf), "%u", st.ftp);      if (lblValFtp)    lv_label_set_text(lblValFtp, buf);
  snprintf(buf, sizeof(buf), "%u", st.http);     if (lblValHttp)   lv_label_set_text(lblValHttp, buf);
  snprintf(buf, sizeof(buf), "%u", st.ping);     if (lblValPing)   lv_label_set_text(lblValPing, buf);

  snprintf(buf, sizeof(buf), "%u", st.total);    if (lblValTotal)  lv_label_set_text(lblValTotal, buf);
  snprintf(buf, sizeof(buf), "%u", ipCount);     if (lblValIps)    lv_label_set_text(lblValIps, buf);
  snprintf(buf, sizeof(buf), "%u", st.creds);    if (lblValCreds)  lv_label_set_text(lblValCreds, buf);
  snprintf(buf, sizeof(buf), "%u", st.payloads); if (lblValPayloads) lv_label_set_text(lblValPayloads, buf);
  snprintf(buf, sizeof(buf), "%u", st.scans);    if (lblValScans)  lv_label_set_text(lblValScans, buf);

  uint32_t mx = max((uint32_t)1, max(st.telnet, max(st.ssh, max(st.ftp, max(st.http, st.ping)))));
  if (barTelnet) lv_bar_set_value(barTelnet, (st.telnet * 100) / mx, LV_ANIM_OFF);
  if (barSsh)    lv_bar_set_value(barSsh,    (st.ssh * 100) / mx, LV_ANIM_OFF);
  if (barFtp)    lv_bar_set_value(barFtp,    (st.ftp * 100) / mx, LV_ANIM_OFF);
  if (barHttp)   lv_bar_set_value(barHttp,   (st.http * 100) / mx, LV_ANIM_OFF);
  if (barPing)   lv_bar_set_value(barPing,   (st.ping * 100) / mx, LV_ANIM_OFF);

  if (lblBarTelnet) { snprintf(buf, sizeof(buf), "%u", st.telnet); lv_label_set_text(lblBarTelnet, buf); }
  if (lblBarSsh)    { snprintf(buf, sizeof(buf), "%u", st.ssh);    lv_label_set_text(lblBarSsh, buf); }
  if (lblBarFtp)    { snprintf(buf, sizeof(buf), "%u", st.ftp);    lv_label_set_text(lblBarFtp, buf); }
  if (lblBarHttp)   { snprintf(buf, sizeof(buf), "%u", st.http);   lv_label_set_text(lblBarHttp, buf); }
  if (lblBarPing)   { snprintf(buf, sizeof(buf), "%u", st.ping);   lv_label_set_text(lblBarPing, buf); }

  esp_lv_adapter_unlock();
}

/* Add a live event to the on-screen table and ticker */
void addEventToUI(const LogEntry &e) {
  if (!esp_lv_adapter_lock(100)) return;

  // Update Ticker
  for (int i = 3; i > 0; i--) {
    if (lblRecentTickers[i] && lblRecentTickers[i - 1]) {
      lv_label_set_text(lblRecentTickers[i], lv_label_get_text(lblRecentTickers[i - 1]));
    }
  }
  if (lblRecentTickers[0]) {
    char tickBuf[128];
    if (e.mac[0] && strcmp(e.mac, "--") != 0) {
      snprintf(tickBuf, sizeof(tickBuf), "[%s] %-6s %s [%s] %s", e.time, e.svc, e.ip, e.mac, e.detail);
    } else {
      snprintf(tickBuf, sizeof(tickBuf), "[%s] %-6s %-15s %s", e.time, e.svc, e.ip, e.detail);
    }
    lv_label_set_text(lblRecentTickers[0], tickBuf);
    uint32_t c = e.color;
    if (!isDarkMode) {
      if (c == 0x3FB950) c = 0x0F5323; // Deep dark green
      else if (c == 0x39C5CF) c = 0x0550AE; // Deep dark blue
      else if (c == 0xD29922) c = 0x8C5303; // Deep dark bronze
      else if (c == 0xF0883E) c = 0xA40E26; // Deep dark orange/crimson
      else if (c == 0xDB61A2) c = 0x5C2B97; // Deep dark purple
      else if (c == 0xF85149) c = 0xA40E26; // Deep dark red
      else c = 0x1F2328; // Pitch charcoal
    }
    lv_obj_set_style_text_color(lblRecentTickers[0], lv_color_hex(c), 0);
  }

  // Update Table (Insert at row 1)
  if (tableLog) {
    uint16_t row_cnt = lv_table_get_row_cnt(tableLog);
    if (row_cnt < 30) {
      lv_table_set_row_cnt(tableLog, row_cnt + 1);
    }
    // Shift rows down
    for (int r = min((int)row_cnt, 29); r >= 2; r--) {
      for (int c = 0; c < 4; c++) {
        lv_table_set_cell_value(tableLog, r, c, lv_table_get_cell_value(tableLog, r - 1, c));
      }
    }
    // Set newest row
    lv_table_set_cell_value(tableLog, 1, 0, e.time);
    lv_table_set_cell_value(tableLog, 1, 1, e.svc);
    char ip_mac_buf[40];
    if (e.mac[0] && strcmp(e.mac, "--") != 0) {
      snprintf(ip_mac_buf, sizeof(ip_mac_buf), "%s [%s]", e.ip, e.mac);
    } else {
      snprintf(ip_mac_buf, sizeof(ip_mac_buf), "%s", e.ip);
    }
    lv_table_set_cell_value(tableLog, 1, 2, ip_mac_buf);
    lv_table_set_cell_value(tableLog, 1, 3, e.detail);
  }

  esp_lv_adapter_unlock();
}

/* Update IP list tab */
void updateIpTableUI() {
  if (!tableIps) return;
  if (!esp_lv_adapter_lock(100)) return;

  uint16_t rows = min((int)ipCount, 40);
  lv_table_set_row_cnt(tableIps, rows + 1);

  for (uint8_t i = 0; i < rows; i++) {
    IPAddress ip(ipTab[i].ip);
    lv_table_set_cell_value(tableIps, i + 1, 0, ip.toString().c_str());
    lv_table_set_cell_value(tableIps, i + 1, 1, ipTab[i].mac[0] ? ipTab[i].mac : "--");

    String svcs;
    if (ipTab[i].mask & 1)  svcs += "TELNET ";
    if (ipTab[i].mask & 2)  svcs += "SSH ";
    if (ipTab[i].mask & 4)  svcs += "FTP ";
    if (ipTab[i].mask & 8)  svcs += "HTTP ";
    if (ipTab[i].mask & 16) svcs += "PING ";
    lv_table_set_cell_value(tableIps, i + 1, 2, svcs.c_str());

    lv_table_set_cell_value(tableIps, i + 1, 3, ipTab[i].flagged ? "PORT SCANNER (FLAGGED)" : "PROBING");
  }

  esp_lv_adapter_unlock();
}

/* Update Loot tab */
void updateLootUI() {
  if (!esp_lv_adapter_lock(100)) return;

  if (tableCreds) {
    uint16_t r = min((int)credCount, 25);
    lv_table_set_row_cnt(tableCreds, r + 1);
    for (int i = 0; i < r; i++) {
      int idx = credCount - 1 - i;
      lv_table_set_cell_value(tableCreds, i + 1, 0, credTab[idx].svc);
      lv_table_set_cell_value(tableCreds, i + 1, 1, credTab[idx].ip);
      lv_table_set_cell_value(tableCreds, i + 1, 2, credTab[idx].user);
      lv_table_set_cell_value(tableCreds, i + 1, 3, credTab[idx].pass);
    }
  }

  if (tablePayloads) {
    uint16_t r = min((int)payloadCount, 25);
    lv_table_set_row_cnt(tablePayloads, r + 1);
    for (int i = 0; i < r; i++) {
      int idx = payloadCount - 1 - i;
      lv_table_set_cell_value(tablePayloads, i + 1, 0, payloadTab[idx].svc);
      lv_table_set_cell_value(tablePayloads, i + 1, 1, payloadTab[idx].ip);
      lv_table_set_cell_value(tablePayloads, i + 1, 2, payloadTab[idx].cmd);
    }
  }

  esp_lv_adapter_unlock();
}

/* Update top status bar badges, battery telemetry, and clock */
void updateStatusBarUI() {
  // Read latest battery telemetry from CH32V003 ADC
  updateBatteryTelemetry();

  if (!esp_lv_adapter_lock(100)) return;

  char ts[16];
  timeStr(ts, sizeof(ts), false);
  if (lblClock) lv_label_set_text(lblClock, ts);

  // Update Header Battery Pill
  if (lblBatteryPill) {
    lv_label_set_text(lblBatteryPill, curBat.pillText);
    if (isDarkMode) {
      if (!curBat.present) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x58A6FF), 0); // USB blue/cyan
      } else if (curBat.charging) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x3FB950), 0); // Green charging
      } else if (curBat.percent <= 15) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0xF85149), 0); // Red low
      } else {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x7EE787), 0); // Bright green
      }
    } else {
      // High contrast colors for Light Mode on light header
      if (!curBat.present) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x0969DA), 0); // Deep sapphire blue
      } else if (curBat.charging) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x1A7F37), 0); // Deep forest green
      } else if (curBat.percent <= 15) {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0xCF222E), 0); // Deep crimson red
      } else {
        lv_obj_set_style_text_color(lblBatteryPill, lv_color_hex(0x1A7F37), 0); // Deep forest green
      }
    }
  }

  // Update System Tab Battery Subsystem Card
  if (barBattery) {
    lv_bar_set_value(barBattery, curBat.percent, LV_ANIM_ON);
    if (curBat.charging) {
      lv_obj_set_style_bg_color(barBattery, isDarkMode ? lv_color_hex(0x3FB950) : lv_color_hex(0x1A7F37), LV_PART_INDICATOR);
    } else if (curBat.percent <= 15) {
      lv_obj_set_style_bg_color(barBattery, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xCF222E), LV_PART_INDICATOR);
    } else {
      lv_obj_set_style_bg_color(barBattery, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), LV_PART_INDICATOR);
    }
  }

  if (lblBatPctVal) {
    char pbuf[32];
    if (curBat.present) {
      snprintf(pbuf, sizeof(pbuf), "%d%%", curBat.percent);
    } else {
      snprintf(pbuf, sizeof(pbuf), "USB 5.0V");
    }
    lv_label_set_text(lblBatPctVal, pbuf);
  }

  if (lblBatStatusVal) {
    lv_label_set_text(lblBatStatusVal, curBat.status);
    if (curBat.charging) {
      lv_obj_set_style_text_color(lblBatStatusVal, isDarkMode ? lv_color_hex(0x3FB950) : lv_color_hex(0x1A7F37), 0);
    } else if (curBat.percent <= 15 && curBat.present) {
      lv_obj_set_style_text_color(lblBatStatusVal, isDarkMode ? lv_color_hex(0xF85149) : lv_color_hex(0xCF222E), 0);
    } else {
      lv_obj_set_style_text_color(lblBatStatusVal, isDarkMode ? lv_color_hex(0x58A6FF) : lv_color_hex(0x0969DA), 0);
    }
  }

  if (lblBatVoltageVal) {
    char vbuf[32];
    snprintf(vbuf, sizeof(vbuf), "%.2f V", curBat.voltage);
    lv_label_set_text(lblBatVoltageVal, vbuf);
  }

  if (lblBatAdcVal) {
    char abuf[32];
    snprintf(abuf, sizeof(abuf), "%u / 1023", curBat.rawAdc);
    lv_label_set_text(lblBatAdcVal, abuf);
  }

  if (lblSdBadge) {
    lv_label_set_text(lblSdBadge, sdOk ? "microSD OK" : "NO SD CARD");
    if (isDarkMode) {
      lv_obj_set_style_text_color(lblSdBadge, sdOk ? lv_color_hex(0x3FB950) : lv_color_hex(0xF85149), 0);
    } else {
      lv_obj_set_style_text_color(lblSdBadge, sdOk ? lv_color_hex(0x1A7F37) : lv_color_hex(0xCF222E), 0);
    }
  }

  if (lblWifiPill) {
    char wbuf[48];
    if (WiFi.status() == WL_CONNECTED) {
      snprintf(wbuf, sizeof(wbuf), "%s (%ddBm)", WiFi.localIP().toString().c_str(), WiFi.RSSI());
    } else {
      snprintf(wbuf, sizeof(wbuf), "WiFi Disconnected");
    }
    lv_label_set_text(lblWifiPill, wbuf);
  }

  if (lblWifiCur && !wifiIsConnecting) {
    char cbuf[96];
    if (WiFi.status() == WL_CONNECTED) {
      snprintf(cbuf, sizeof(cbuf), "Connected: %s | %s (%ddBm)",
               WiFi.SSID().c_str(), WiFi.localIP().toString().c_str(), WiFi.RSSI());
    } else {
      snprintf(cbuf, sizeof(cbuf), "Status: Disconnected / Offline");
    }
    lv_label_set_text(lblWifiCur, cbuf);
  }

  if (lblHeapPill) {
    char hbuf[32];
    snprintf(hbuf, sizeof(hbuf), "%uk free", ESP.getFreeHeap() / 1024);
    lv_label_set_text(lblHeapPill, hbuf);
  }

  esp_lv_adapter_unlock();
}


/*=================== 15. SETUP / LOOP ==========================*/
void setup() {
  // Prevent WiFi stack from writing to NVS SPI Flash (which disables CPU cache and crashes RGB LCD)
  WiFi.persistent(false);

  Serial.begin(115200);
  printf("\n[VERA] Bootloader handed over to setup()...\n");
  fflush(stdout);

  // Allow time for native USB CDC to enumerate so startup logs are captured
  unsigned long _waitStart = millis();
  while (!Serial && (millis() - _waitStart < 2000)) {
    delay(10);
  }
  delay(100);

  Serial.println("\n========================================================");
  Serial.println("  VERA // Waveshare ESP32-S3-Touch-LCD-7B");
  Serial.println("========================================================");
  Serial.printf("[SYSTEM] Chip: %s | Rev: %d | Cores: %d\n", ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores());
  Serial.printf("[SYSTEM] Flash: %u MB | PSRAM: %u MB\n", ESP.getFlashChipSize() / (1024 * 1024), ESP.getPsramSize() / (1024 * 1024));
  Serial.printf("[SYSTEM] Free Heap: %u KB | Free PSRAM: %u KB\n", ESP.getFreeHeap() / 1024, ESP.getFreePsram() / 1024);

  // Check for Octal PSRAM (Required for 1024x600 RGB parallel double-buffer)
  if (!psramFound() || ESP.getPsramSize() < (2 * 1024 * 1024)) {
    Serial.println("\n********************************************************");
    Serial.println("  [CRITICAL ERROR] PSRAM IS NOT ENABLED!");
    Serial.println("  The 7.0\" 1024x600 RGB display requires 8MB Octal PSRAM.");
    Serial.println("  In Arduino IDE, open the Tools menu and configure:");
    Serial.println("    -> Tools > PSRAM: 'OPI PSRAM'");
    Serial.println("    -> Tools > Flash Size: '16MB (128Mb)'");
    Serial.println("    -> Tools > Partition Scheme: '16M Flash (3MB APP/9.9MB FATFS)'");
    Serial.println("********************************************************\n");
    Serial.println("[HALT] System paused to prevent boot loop. Please reflash with OPI PSRAM enabled.");
    while (true) {
      delay(2000);
      Serial.println("[HALT] Awaiting reflash with: Tools > PSRAM > 'OPI PSRAM'");
    }
  }

#if ALERT_PIN >= 0
  pinMode(ALERT_PIN, OUTPUT);
  digitalWrite(ALERT_PIN, LOW);
#endif

  memset(&st, 0, sizeof(st));
  memset(ipTab, 0, sizeof(ipTab));

  tn.active = false; tn.stage = 0; tn.tries = 0; tn.last = 0;
  ft.active = false; ft.stage = 0; ft.tries = 0; ft.last = 0;

  // 1. Mount the MicroSD Card via SDMMC (runs before LCD to avoid cache-disable conflicts)
  Serial.println("[INIT] Mounting MicroSD Card via SDMMC...");
  sdOk = mountSD();
  bool restored = false;
  if (sdOk) {
    restored = loadState();
    st.boots++;
    Serial.printf("[STATE] %s | Boot #%u | %u prior hits\n",
                  restored ? "Restored from card" : "Fresh state initialized",
                  st.boots, st.total);
  } else {
    st.boots++;
    Serial.println("[WARN] Running without persistent MicroSD storage");
  }

  // 2. Connect to Wi-Fi (completed before starting RGB LCD DMA)
  loadWifiConfig();
  Serial.printf("[WIFI] Connecting to %s...\n", curWifiSsid);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_STA);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  WiFi.setHostname(FAKE_HOST);
  WiFi.setSleep(false);
  WiFi.begin(curWifiSsid, curWifiPass);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 4000) {
    delay(200);
    Serial.print('.');
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WIFI] Connected! Local IP: %s\n", WiFi.localIP().toString().c_str());
    configTime(GMT_OFFSET_SEC, DST_OFFSET_SEC, "pool.ntp.org", "time.nist.gov");
    ntpConfigured = true;
  } else {
    Serial.println("\n[WIFI] Connection pending. Operating offline.");
  }

  // 3. Initialize hardware: GT911 Touch, RGB LCD Panel, and Backlight
  Serial.println("[INIT] Initializing capacitive touch (GT911)...");
  esp_lcd_touch_handle_t tp_handle = touch_gt911_init();
  if (tp_handle) {
    Serial.println("[INIT] GT911 touch initialized successfully.");
  } else {
    Serial.println("[WARN] GT911 touch not detected or init skipped; continuing.");
  }

  Serial.println("[INIT] Initializing 1024x600 RGB LCD panel...");
  esp_lcd_panel_handle_t panel_handle = waveshare_esp32_s3_rgb_lcd_init();
  if (!panel_handle) {
    Serial.println("\n********************************************************");
    Serial.println("  [CRITICAL ERROR] RGB LCD panel allocation failed!");
    Serial.println("  Make sure PSRAM is set to 'OPI PSRAM' in Arduino IDE.");
    Serial.println("********************************************************\n");
    while (true) {
      delay(2000);
      Serial.println("[HALT] Display driver halted to prevent boot loop.");
    }
  }
  Serial.println("[INIT] RGB LCD panel initialized.");

  // Keep backlight OFF during LVGL setup to eliminate boot lines and white flashes
  IO_EXTENSION_Init();
  IO_EXTENSION_Pwm_Output(0);
  wavesahre_rgb_lcd_bl_off();

  // 4. Initialize LVGL port adapter on Core 1
  Serial.println("[INIT] Initializing LVGL display and input drivers...");
  esp_err_t lv_err = esp_lv_adapter_init(panel_handle, tp_handle);
  if (lv_err != ESP_OK) {
    Serial.printf("[ERROR] esp_lv_adapter_init failed: 0x%x\n", lv_err);
    while (true) {
      delay(2000);
      Serial.println("[HALT] LVGL init failed.");
    }
  }
  Serial.println("[INIT] LVGL port initialized.");

  // 5. Show boot splash then build the real GUI
  showSplash();
  createUI();
  applyTheme(isDarkMode);

  if (restored) {
    applyTheme(isDarkMode);
    IO_EXTENSION_Pwm_Output(currentBrightness);
    if (sliderBrightness && esp_lv_adapter_lock(100)) {
      lv_slider_set_value(sliderBrightness, currentBrightness, LV_ANIM_OFF);
      if (lblBrightnessVal) {
        char bBuf[16];
        snprintf(bBuf, sizeof(bBuf), "%d%%", currentBrightness);
        lv_label_set_text(lblBrightnessVal, bBuf);
      }
      esp_lv_adapter_unlock();
    }
  }

  // Start decoy servers
  srvTelnet.begin();
  srvSSH.begin();
  srvFTP.begin();
  srvHTTP.begin();
  srvAdmin.begin();
  srvTelnet.setNoDelay(true);
  srvHTTP.setNoDelay(true);

  // Start lwIP raw ICMP echo interception
  startIcmpWatch();

  // Initial UI refresh
  updateDashboardMetrics();
  updateIpTableUI();
  updateLootUI();
  updateStatusBarUI();

  // Allow LVGL 80ms to render the initial styled frame into DMA buffers before turning on backlight
  delay(80);

  // Turn ON LCD backlight cleanly now that UI is fully loaded and themed
  Serial.printf("[INIT] Enabling LCD backlight cleanly (%d%% PWM)...\n", currentBrightness);
  IO_EXTENSION_Pwm_Output(currentBrightness);
  wavesahre_rgb_lcd_bl_on();

  logEvent("SYS", WiFi.localIP(),
           String(sdOk ? "System Armed" : "System Armed (NO SD)") + " Boot #" + String(st.boots),
           0x8B949E, false);
  saveState(true);
  Serial.println("[READY] VERA Armed & Monitoring.");
  printf("[READY] VERA Armed & Monitoring.\n");
  fflush(stdout);
}

void loop() {
  serviceIcmp();
  handleTelnet();
  handleSSH();
  handleFTP();
  handleHTTP();
  handleAdmin();

  static uint32_t lastClockSec = 0;
  static uint32_t lastWiFiAttempt = 0;
  if ((millis() - lastClockSec) > 1000) {
    lastClockSec = millis();
    updateStatusBarUI();
    saveState(false);

    if (WiFi.status() != WL_CONNECTED) {
      if (!wifiIsConnecting && !wifiIsScanning && (millis() - lastWiFiAttempt) > 15000) {
        lastWiFiAttempt = millis();
        Serial.printf("[WIFI] Disconnected - retrying %s...\n", curWifiSsid);
        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        esp_wifi_disconnect();
        WiFi.begin(curWifiSsid, curWifiPass);
      }
    } else {
      lastWiFiAttempt = millis();
      if (!ntpConfigured) {
        configTime(GMT_OFFSET_SEC, DST_OFFSET_SEC, "pool.ntp.org", "time.nist.gov");
        ntpConfigured = true;
        Serial.printf("[NTP] Connected to network. Synchronizing time with %s\n", WiFi.localIP().toString().c_str());
      }
    }
  }
  delay(2);
}
