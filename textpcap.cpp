#include "textpcap.h"
#include <iostream>

TextPcap::TextPcap(const char *filename) : Pcap::Pcap(filename) {}
void TextPcap::loop() {
  Pcap::loop();
  std::cout << "Total size of captured packets: " << total_packets_size
            << std::endl;
  std::cout << "Amount of packets handled: " << packet_count << std::endl;
}

void TextPcap::packet_handler(const struct pcap_pkthdr *header,
                              std::vector<uint8_t> data) {
  total_packets_size += header->caplen;
  ++packet_count;
  if (might_be_tox_dht(data) && is_ipv4(data)) {
    std::cout << header->ts.tv_sec << "." << header->ts.tv_usec << "\t"
              << src_ip(data) << " > " << dst_ip(data) << "\t("
              << header->caplen << " bytes)" << std::endl;

    int udp_payload_offset = get_udp_payload_offset(data);
    if (data.size() >= udp_payload_offset) {
      for (auto it = data.begin() + udp_payload_offset; it != data.end();
           ++it) {
        std::cout << std::hex << (int)*it << std::dec;
      }
      std::cout << std::endl;
    }
  } else {
    std::cout << "\tPacket does not seem to be a Tox DHT packet" << std::endl;
  }
}
