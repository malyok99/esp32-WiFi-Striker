#include "src/core/globals.h"
#include "src/output/lcd_handler.h"
#include "src/input/input_handler.h"
#include "src/modules/wifi_scanner.h"
#include "src/modules/attack_modes.h"

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
