#ifndef TEXTPCAP_H
#define TEXTPCAP_H

#include "pcap.h"

class TextPcap : public Pcap<TextPcap> {
public:
  TextPcap(const char *);
  void packet_handler(time_t, uint32_t, uint32_t, const uint8_t *);
  void before_loop();
  void after_loop();

private:
  size_t total_packets_size;
  size_t packet_count;
  constexpr static const char *date_format = "%F %T";

  std::string ip_address_v4(const uint8_t *);
  std::string ip_address_v6(const uint8_t *);
  std::string nonce(const uint8_t *);
  std::string public_key(const uint8_t *);
  std::string packet_type(DhtPacketType);
};

#endif // TEXTPCAP_H
