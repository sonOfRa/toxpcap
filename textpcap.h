#ifndef TEXTPCAP_H
#define TEXTPCAP_H

#include "pcap.h"

class TextPcap : public Pcap {
public:
  TextPcap(const char *);
  void packet_handler(uint32_t packet_sec, uint32_t packet_usec,
                      const std::vector<uint8_t> &);
  void loop();

private:
  size_t total_packets_size;
  size_t packet_count;
};

#endif // TEXTPCAP_H
