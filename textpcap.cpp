#include "textpcap.h"

#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <sstream>

TextPcap::TextPcap(const char *filename) : Pcap::Pcap(filename) {}

void TextPcap::before_loop() {
  total_packets_size = 0;
  packet_count = 0;
}

void TextPcap::after_loop() {
  std::cout << "Total size of captured packets: " << total_packets_size
            << std::endl;
  std::cout << "Amount of packets handled: " << packet_count << std::endl;
}

void TextPcap::packet_handler(time_t sec, uint32_t usec, uint32_t len,
                              const uint8_t *data) {
  total_packets_size += len;
  ++packet_count;
  if (might_be_tox_dht(data, len)) {
    struct tm *timeinfo;
    timeinfo = localtime(&sec);
    char buffer[100];
    strftime(buffer, 100, date_format, timeinfo);
    std::cout << buffer << "." << usec << "\t";
    std::string src = is_ipv4(data) ? ip_address_v4(src_ip(data))
                                    : ip_address_v6(src_ip(data));
    std::string dst = is_ipv4(data) ? ip_address_v4(dst_ip(data))
                                    : ip_address_v6(dst_ip(data));
    std::cout << src << " -> " << dst << "\t(" << len << " bytes)" << std::endl;
    std::cout << "\tPacket Type: " << packet_type(get_dht_packet_type(data))
              << std::endl;
    std::cout << "\tPublic Key: " << public_key(get_dht_public_key(data))
              << std::endl;
    std::cout << "\tNonce: " << nonce(get_dht_nonce(data)) << std::endl;
  }

  //  if (might_be_tox_dht(data) && is_ipv4(data)) {
  //    std::cout << header->ts.tv_sec << "." << header->ts.tv_usec << "\t"
  //              << src_ip(data) << " > " << dst_ip(data) << "\t("
  //              << header->caplen << " bytes)" << std::endl;

  //    int udp_payload_offset = get_udp_payload_offset(data);
  //    if (data.size() >= udp_payload_offset) {
  //      for (auto it = data.begin() + udp_payload_offset; it != data.end();
  //           ++it) {
  //        std::cout << std::hex << (int)*it << std::dec;
  //      }
  //      std::cout << std::endl;
  //    }
  //  } else {
  //    std::cout << "\tPacket does not seem to be a Tox DHT packet" <<
  //    std::endl;
  //  }
}

std::string TextPcap::ip_address_v4(const uint8_t *input) {
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, input, buf, INET_ADDRSTRLEN);
  return buf;
}

std::string TextPcap::ip_address_v6(const uint8_t *input) {
  char buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, input, buf, INET6_ADDRSTRLEN);
  return buf;
}

std::string TextPcap::nonce(const uint8_t *input) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < tox_nonce_size; ++i) {
    ss << (int)input[i];
  }
  return ss.str();
}

std::string TextPcap::public_key(const uint8_t *input) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < tox_public_key_size; ++i) {
    ss << (int)input[i];
  }
  return ss.str();
}

std::string TextPcap::packet_type(DhtPacketType type) {
  switch (type) {
  case DhtPacketType::echo_request:
    return "Echo Request";
  case DhtPacketType::echo_response:
    return "Echo Response";
  case DhtPacketType::nodes_request:
    return "Nodes Request";
  case DhtPacketType::nodes_response:
    return "Nodes Response";
  default:
    return "Unknown";
  }
}
