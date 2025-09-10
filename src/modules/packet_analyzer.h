#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include "../core/globals.h"

void analyzePacket(const wifi_promiscuous_pkt_t* pkt);
String getProtocolName(uint8_t type);
String macToString(const uint8_t* mac);
void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type);
void parseMacAddress(const String &macStr, uint8_t* macAddr);

#endif
