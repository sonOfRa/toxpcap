#include <vector>
#include <cstdint>
#include <pcap/pcap.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

#include "pcap.h"

/**
 * @brief Pcap::Pcap Construct a new instance for a pcap file
 * @param filename filename of the pcap file to use
 * @throws runtime_error if the file can't be found or is not a pcap file
 */
Pcap::Pcap(const char *filename) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_instance = pcap_open_offline(filename, errbuf);
  if (!pcap_instance)
    throw std::runtime_error(errbuf);
}

Pcap::~Pcap() {}

/**
 * When overriding this method, you should make sure that you invoke the base
 * implementation as well.
 * @brief Pcap::loop Invokes packet_handler for each packet in the pcap file
 */
void Pcap::loop() {
  pcap_loop(pcap_instance, 0, internal_loop, (u_char *)((void *)this));
}

void Pcap::internal_loop(u_char *user_data, const struct pcap_pkthdr *header,
                         const u_char *pkt_data) {
  std::vector<uint8_t> data =
      std::vector<uint8_t>(pkt_data, pkt_data + header->caplen);
  ((Pcap *)user_data)->packet_handler(header, data);
}

/**
 * @brief Pcap::is_udp checks whether the packet is a UDP packet
 * @param pkt_data the packet to check
 * @return true if the packet is UDP
 */
bool Pcap::is_udp(std::vector<uint8_t> pkt_data) {
  return pkt_data.at(ip_protocol_offset) == ip_protocol_udp;
}

/**
 * @brief Pcap::is_udp checks whether the packet is a TCP packet
 * @param pkt_data the packet to check
 * @return true if the packet is TCP
 */
bool Pcap::is_tcp(std::vector<uint8_t> pkt_data) {
  return pkt_data.at(ip_protocol_offset) == ip_protocol_tcp;
}

/**
 * @brief Pcap::is_ipv4 checks whether the packet is an IPv4 packet
 * @param pkt_data the packet to check
 * @return true if packet is IPv4
 */
bool Pcap::is_ipv4(std::vector<uint8_t> pkt_data) {
  return hi_nibble(pkt_data.at(ethernet_frame_size)) == ip_version_v4;
}

/**
 * Test whether this packet might be a tox DHT packet. It must meet the
 * following criteria:
 * - UDP
 * - payload length of at least 1 (type) + 32 (public key) + 24 (nonce) bytes
 * - Type must be 0x00 (EchoRequest), 0x01 (EchoResponse), 0x02 (NodesRequest)
 * or 0x04 (NodesResponse)
 * @brief might_be_tox_dht check whether this packet might be a tox dht packet
 * @param pkt_data the packet to check
 * @return true if the packet might be a tox DHT packet
 */
bool Pcap::might_be_tox_dht(std::vector<uint8_t> pkt_data) {
  if (!is_udp(pkt_data)) {
    return false;
  }

  size_t payload_length = pkt_data.size() - get_udp_payload_offset(pkt_data);
  if (payload_length < 1 + tox_public_key_size + tox_nonce_size) {
    return false;
  }

  if (get_dht_packet_type(pkt_data) == DhtPacketType::unknown) {
    return false;
  }
  return true;
}

/**
 * Causes undefined behaviour of packet is not a DHT packet
 * @brief Pcap::get_dht_packet_type type of the DHT packet
 * @return the type of the DHT packet
 */
Pcap::DhtPacketType Pcap::get_dht_packet_type(std::vector<uint8_t> pkt_data) {
  uint8_t type = pkt_data.at(get_udp_payload_offset(pkt_data));
  if (type != 0x00 && type != 0x01 && type != 0x02 && type != 0x04) {
    return DhtPacketType::unknown;
  }
  return DhtPacketType(type);
}

/**
 * Causes undefined behaviour if packet is not a DHT packet
 * @brief Pcap::get_dht_public_key the public key of the DHT packet
 * @return
 */
std::vector<uint8_t> Pcap::get_dht_public_key(std::vector<uint8_t>) {}

std::vector<uint8_t> Pcap::get_dht_nonce(std::vector<uint8_t>) {}

/**
 * @brief Pcap::src_ip get the source IP of a packet
 * @param pkt_data the packet
 * @return the source IP of the packet
 */
std::string Pcap::src_ip(std::vector<uint8_t> pkt_data) {
  std::ostringstream s;
  for (int i = ip_src_offset; i < ip_src_offset + 4; i++) {
    s << (int)pkt_data.at(i);
    if (i < ((ip_src_offset + 4) - 1)) {
      s << ".";
    }
  }
  return std::string(s.str());
}

/**
 * @brief Pcap::dst_ip get the destination IP of a packet
 * @param pkt_data the packet
 * @return the destination IP of the packet
 */
std::string Pcap::dst_ip(std::vector<uint8_t> pkt_data) {
  std::ostringstream s;
  for (int i = ip_dst_offset; i < ip_dst_offset + 4; i++) {
    s << (int)pkt_data.at(i);
    if (i < ((ip_dst_offset + 4) - 1)) {
      s << ".";
    }
  }
  return std::string(s.str());
}

/**
 * Get the offset (in bytes) of the UDP payload in the specified packet. Note
 * that this function does not guarantee that there actually is a non-empty
 * payload.
 * @brief get_udp_payload_offset Get the offset of the UDP payload in a packet
 * @return The offset of the UDP payload in this packet (in bytes). 0 if the
 * packet is not a UDP packet.
 */
uint8_t Pcap::get_udp_payload_offset(std::vector<uint8_t> pkt_data) {
  if (!is_udp(pkt_data)) {
    return 0;
  }
  uint8_t ihl = lo_nibble(pkt_data.at(ethernet_frame_size));
  uint8_t ip_header_bits = ihl * 32;
  uint8_t ip_header_bytes = ip_header_bits / 8;

  return ethernet_frame_size + ip_header_bytes + udp_data_offset;
}
