#include "packet_analyzer.h"

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
