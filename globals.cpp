#include "globals.h"

// Initialize global variables
LiquidCrystal lcd(14, 27, 26, 25, 33, 32);

// Joystick pins
const int joyX = 35;
const int joyY = 34;
const int joyBtn = 2;

// Application states
AppState currentState = MAIN_MENU;

// Menu items
const char* menuItems[] = {"SCAN", "SELECT", "ATTACK", "INFO"};
const char* attackMenuItems[] = {"PS", "MITM", "AP"};
int menuIndex = 0;
int attackMenuIndex = 0;
int selectedNetwork = -1;

// Wi-Fi networks
WiFiNetwork networks[20];
int networkCount = 0;
int scrollPos = 0;

// Info page scrolling
int infoPage = 0;
const int INFO_PAGES = 3;

// Input filtering
unsigned long lastAction = 0;
const int DEBOUNCE_DELAY = 200;

// Text scrolling
unsigned long lastScroll = 0;
const int SCROLL_DELAY = 500;
int textOffset = 0;

// Packet monitoring
volatile int packetCount = 0;
uint8_t targetBSSID[6] = {0};
unsigned long lastPacketReset = 0;
const int PACKET_WINDOW = 1000;

// Packet sniffing variables
std::vector<String> packetLogs;
unsigned long lastPacketLog = 0;
const int MAX_PACKET_LOGS = 20;

// MITM variables
std::vector<String> mitmLogs;
std::vector<String> mitmCredentials;
unsigned long lastMitmLog = 0;
const int MAX_MITM_LOGS = 30;
WebServer mitmServer(80);
DNSServer mitmDnsServer;
IPAddress apIP(192, 168, 4, 1);
unsigned int mitmClientCount = 0;
bool isCaptivePortal = true;
int mitmPage = 0;

// AP mode variables
String apSSID = "Weak_WiFi(hackme)";
String apPassword = "";
unsigned int apClientCount = 0;
unsigned long lastAPUpdate = 0;
std::vector<String> apLogs;
std::vector<String> connectedDevices;
WebServer apServer(80);
int apPage = 0;

// Protocol analysis
int httpCount = 0;
int dnsCount = 0;
int arpCount = 0;
int tcpCount = 0;
int udpCount = 0;
