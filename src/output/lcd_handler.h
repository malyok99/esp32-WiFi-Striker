#ifndef LCD_HANDLER_H
#define LCD_HANDLER_H

#include "../core/globals.h"

void showMainMenu();
void showScanResults();
void showSelectScreen();
void showInfoScreen();
void showAttackMenu();
String getEncryptionType(wifi_auth_mode_t type);
String getBandwidth(const WiFiNetwork& net);

#endif
