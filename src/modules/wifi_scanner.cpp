#include "wifi_scanner.h"
#include "../output/lcd_handler.h"

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

void enterScanMode() {
  currentState = SCAN_MODE;
  networkCount = 0;
  scrollPos = 0;
  lcd.clear();
  lcd.print("Scanning...");
  WiFi.scanNetworks(true, true);
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

void enterAttackMode() {
  currentState = ATTACK_MENU;
  attackMenuIndex = 0;
  showAttackMenu();
}
