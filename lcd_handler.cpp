#include "lcd_handler.h"

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

String getBandwidth(const WiFiNetwork& net) {
  return (net.channel > 14) ? "5GHz" : "2.4GHz";
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
