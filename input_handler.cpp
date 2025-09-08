#include "input_handler.h"
#include "lcd_handler.h"
#include "wifi_scanner.h"
#include "attack_modes.h"

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
