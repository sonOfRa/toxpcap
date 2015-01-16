#ifndef TEXTPCAP_H
#define TEXTPCAP_H

#include "pcap.h"

class TextPcap : public Pcap {
public:
  TextPcap(const char *);
  void packet_handler(const struct pcap_pkthdr *, std::vector<uint8_t>);
  void loop();
private:
  size_t total_packages_size;
};

#endif // TEXTPCAP_H
