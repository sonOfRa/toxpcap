#ifndef PCAP_H
#define PCAP_H

#include <cstdint>
#include <vector>
#include <string>

/**
 * @brief Base Class for Pcap functions. Currently limited to IPv4 only
 * functionality.
 */
template<class PcapType>
class Pcap {
public:
  Pcap(const char *);
  ~Pcap();

  enum class DhtPacketType : uint8_t {
    echo_request = 0x00,
    echo_response = 0x01,
    nodes_request = 0x02,
    nodes_response = 0x04,
    unknown
  };

  void packet_handler(uint32_t, uint32_t, uint32_t, const uint8_t *);
  void loop();

  bool is_udp(const uint8_t *);
  bool is_tcp(const uint8_t *);
  bool is_ipv4(const uint8_t *);

  bool might_be_tox_dht(const uint8_t *, uint32_t);
  DhtPacketType get_dht_packet_type(const uint8_t *);
  const uint8_t *get_dht_public_key(const uint8_t *);
  const uint8_t *get_dht_nonce(const uint8_t *);

  std::string src_ip(const uint8_t *);
  std::string dst_ip(const uint8_t *);

  uint8_t get_udp_payload_offset(const uint8_t *);

  static inline uint8_t lo_nibble(uint8_t byte) { return byte & 0x0F; }

  static inline uint8_t hi_nibble(uint8_t byte) { return (byte >> 4) & 0x0F; }

  static const int pcap_header_size = 4 + 2 + 2 + 4 + 4 + 4 + 4;
  static const int pcap_rec_header_size = 4 + 4 + 4 + 4;

  static const int ethernet_frame_size = 14;
  static const int ip_version_v4 = 4;
  static const int ip_protocol_offset = ethernet_frame_size + 9;
  static const int ip_protocol_tcp = 6;
  static const int ip_protocol_udp = 17;
  static const int ip_src_offset = ip_protocol_offset + 3;
  static const int ip_dst_offset = ip_src_offset + 4;
  static const int udp_data_offset = 8;

  static const int tox_public_key_size = 32;
  static const int tox_nonce_size = 24;

private:
  int fd;
  uint8_t *mmap_address;
  off_t file_size;
};

#endif // PCAP_H
