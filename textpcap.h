#ifndef TEXTPCAP_H
#define TEXTPCAP_H

#include "pcap.h"

class TextPcap : public Pcap {
public:
  TextPcap(const char *);
  void packet_handler(const struct pcap_pkthdr *, const std::vector<uint8_t>&);
  void loop();
private:
  size_t total_packets_size;
  size_t packet_count;
};

#endif // TEXTPCAP_H
