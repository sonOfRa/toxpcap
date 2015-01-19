#ifndef PCAP_H
#define PCAP_H

#include <cstdint>
#include <vector>
#include <string>

/**
 * @brief Base Class for Pcap functions. Currently limited to IPv4 only
 * functionality.
 */
template <class PcapType> class Pcap {
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
  bool inline is_ipv4(const uint8_t *pkt_data) {
    return hi_nibble(pkt_data[ethernet_frame_size]) == ip_version_v4;
  }

  bool inline is_ipv6(const uint8_t *pkt_data) {
    return hi_nibble(pkt_data[ethernet_frame_size]) == ip_version_v6;
  }

  bool might_be_tox_dht(const uint8_t *, uint32_t);
  DhtPacketType get_dht_packet_type(const uint8_t *);
  const uint8_t *get_dht_public_key(const uint8_t *);
  const uint8_t *get_dht_nonce(const uint8_t *);

  const uint8_t *src_ip(const uint8_t *);
  const uint8_t *dst_ip(const uint8_t *);

  uint8_t get_udp_payload_offset_v4(const uint8_t *);

  static inline uint8_t lo_nibble(uint8_t byte) { return byte & 0x0F; }

  static inline uint8_t hi_nibble(uint8_t byte) { return (byte >> 4) & 0x0F; }

  static const uint8_t pcap_header_size = 4 + 2 + 2 + 4 + 4 + 4 + 4;
  static const uint8_t pcap_rec_header_size = 4 + 4 + 4 + 4;

  static const uint8_t ethernet_frame_size = 14;
  static const uint8_t ip_version_v4 = 4;
  static const uint8_t ip_version_v6 = 6;
  static const uint8_t ip_protocol_offset = ethernet_frame_size + 9;
  static const uint8_t ip_protocol_tcp = 6;
  static const uint8_t ip_protocol_udp = 17;
  static const uint8_t ip_v4_src_offset = ip_protocol_offset + 3;
  static const uint8_t ip_v4_dst_offset = ip_v4_src_offset + 4;
  static const uint8_t udp_data_offset = 8;

  static const uint8_t ip_v6_next_header_offset = ethernet_frame_size + 6;
  static const uint8_t ip_v6_header_size = 40;
  static const uint8_t ip_v6_udp_payload_offset =
      ethernet_frame_size + ip_v6_header_size + udp_data_offset;
  static const uint8_t ip_v6_src_offset = ethernet_frame_size + 8;
  static const uint8_t ip_v6_dst_offset = ip_v6_src_offset + 16;

  static const uint8_t tox_public_key_size = 32;
  static const uint8_t tox_nonce_size = 24;

private:
  int fd;
  uint8_t *mmap_address;
  off_t file_size;
};

#endif // PCAP_H
