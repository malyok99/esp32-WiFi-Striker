#ifndef GLOBALS_H
#define GLOBALS_H

#include <WiFi.h>
#include <LiquidCrystal.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <vector>
#include <algorithm>

// LCD setup (4-bit interface)
extern LiquidCrystal lcd;

// Joystick pins
extern const int joyX;
extern const int joyY;
extern const int joyBtn;

// Application states
enum AppState { 
  MAIN_MENU, SCAN_MODE, SCAN_RESULTS, SELECT_MODE, INFO_MODE, 
  ATTACK_MODE, ATTACK_MENU, PS_MODE, MITM_MODE, AP_MODE 
};
extern AppState currentState;

// Menu items
extern const char* menuItems[];
extern const char* attackMenuItems[];
extern int menuIndex;
extern int attackMenuIndex;
extern int selectedNetwork;

// Wi-Fi networks
struct WiFiNetwork {
  String ssid;
  int32_t rssi;
  uint8_t channel;
  String bssid;
  String encryption;
};
extern WiFiNetwork networks[20];
extern int networkCount;
extern int scrollPos;

// Info page scrolling
extern int infoPage;
extern const int INFO_PAGES;

// Input filtering
extern unsigned long lastAction;
extern const int DEBOUNCE_DELAY;

// Text scrolling
extern unsigned long lastScroll;
extern const int SCROLL_DELAY;
extern int textOffset;

// Packet monitoring
extern volatile int packetCount;
extern uint8_t targetBSSID[6];
extern unsigned long lastPacketReset;
extern const int PACKET_WINDOW;

// Packet sniffing variables
extern std::vector<String> packetLogs;
extern unsigned long lastPacketLog;
extern const int MAX_PACKET_LOGS;

// MITM variables
extern std::vector<String> mitmLogs;
extern std::vector<String> mitmCredentials;
extern unsigned long lastMitmLog;
extern const int MAX_MITM_LOGS;
extern WebServer mitmServer;
extern DNSServer mitmDnsServer;
extern IPAddress apIP;
extern unsigned int mitmClientCount;
extern bool isCaptivePortal;
extern int mitmPage;

// AP mode variables
extern String apSSID;
extern String apPassword;
extern unsigned int apClientCount;
extern unsigned long lastAPUpdate;
extern std::vector<String> apLogs;
extern std::vector<String> connectedDevices;
extern WebServer apServer;
extern int apPage;

// Protocol analysis
extern int httpCount;
extern int dnsCount;
extern int arpCount;
extern int tcpCount;
extern int udpCount;

#endif
