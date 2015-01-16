#ifndef PCAP_H
#define PCAP_H

#include <cstdint>
#include <pcap/pcap.h>
#include <vector>
#include <string>

/**
 * @brief Base Class for Pcap functions. Currently limited to IPv4 only
 * functionality.
 */
class Pcap {
public:
  Pcap(const char *);
  virtual ~Pcap();

  enum class DhtPacketType : uint8_t {
      echo_request = 0x00,
      echo_response = 0x01,
      nodes_request = 0x02,
      nodes_response = 0x04,
      unknown
  };

  virtual void packet_handler(const struct pcap_pkthdr *,
                              const std::vector<uint8_t>&) = 0;
  virtual void loop();

  bool is_udp(const std::vector<uint8_t>&);
  bool is_tcp(const std::vector<uint8_t>&);
  bool is_ipv4(const std::vector<uint8_t>&);

  bool might_be_tox_dht(const std::vector<uint8_t>&);
  DhtPacketType get_dht_packet_type(const std::vector<uint8_t>&);
  std::vector<uint8_t> get_dht_public_key(const std::vector<uint8_t>&);
  std::vector<uint8_t> get_dht_nonce(const std::vector<uint8_t>&);
  std::vector<uint8_t> get_dht_payload(const std::vector<uint8_t>&);

  std::string src_ip(const std::vector<uint8_t>&);
  std::string dst_ip(const std::vector<uint8_t>&);

  uint8_t get_udp_payload_offset(const std::vector<uint8_t>&);

  static inline uint8_t lo_nibble(uint8_t byte) { return byte & 0x0F; }

  static inline uint8_t hi_nibble(uint8_t byte) { return (byte >> 4) & 0x0F; }

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
  pcap_t *pcap_instance;
  static void internal_loop(u_char *, const struct pcap_pkthdr *,
                            const u_char *);
  std::vector<uint8_t> current_packet;
};

#endif // PCAP_H
