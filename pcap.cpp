#include <vector>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string>
#include <byteswap.h>

#include "pcap.h"

#include "textpcap.h"
#include "sqlitepcap.h"

/**
 * @brief Pcap::Pcap Construct a new instance for a pcap file
 * @param filename filename of the pcap file to use
 * @throws runtime_error if the file can't be found or is not a pcap file
 */
template <typename PcapType> Pcap<PcapType>::Pcap(const char *filename) {
  fd = open(filename, O_RDONLY);
  if (fd == -1) {
    char str[256];
    strcpy(str, "Could not open file for reading: ");
    strcat(str, strerror(errno));
    throw std::runtime_error(str);
  }

  struct stat statbuf;
  if (fstat(fd, &statbuf) < 0) {
    char str[256];
    strcpy(str, "Could not get file size: ");
    strcat(str, strerror(errno));
    throw std::runtime_error(str);
  }

  file_size = statbuf.st_size;
  mmap_address =
      (uint8_t *)mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (mmap_address == (void *)-1) {
    char str[256];
    strcpy(str, "Could not map file into memory: ");
    strcat(str, strerror(errno));
    throw std::runtime_error(str);
  }

  if (close(fd) == -1) {
    char str[256];
    strcpy(str, "Failed to close file: ");
    strcat(str, strerror(errno));
    throw std::runtime_error(str);
  }

  uint32_t magic_number = ((uint32_t *)mmap_address)[0];
  if (magic_number == 0xa1b2c3d4 || magic_number == 0xa1b23c4d) {
  } else if (magic_number == 0xd4c3b2a1 || magic_number == 0x4d3cb2a1) {
    abort();
  } else {
    throw std::runtime_error("File is not a pcap file");
  }
}

template <typename PcapType> Pcap<PcapType>::~Pcap() {
  if (munmap(mmap_address, file_size) == -1) {
    std::cerr << "Failed to unmap the file. This shouldn't happen. Something "
                 "went really really wrong :(" << std::endl;
  }
}

/**
 * When overriding this method, you should make sure that you invoke the base
 * implementation as well.
 * @brief Pcap::loop Invokes packet_handler for each packet in the pcap file
 */
template <typename PcapType> void Pcap<PcapType>::loop() {
  static_cast<PcapType *>(this)->before_loop();
  uint64_t offset = pcap_header_size;
  while (offset < (uint64_t)file_size) {
    uint8_t *current = mmap_address + offset;
    uint32_t packet_sec = ((uint32_t *)current)[0];
    uint32_t packet_usec = ((uint32_t *)current)[1];
    uint32_t packet_len = ((uint32_t *)current)[2];

    uint8_t *current_packet = current + pcap_rec_header_size;

    static_cast<PcapType *>(this)
        ->packet_handler(packet_sec, packet_usec, packet_len, current_packet);

    offset += pcap_rec_header_size + packet_len;
  }
  static_cast<PcapType *>(this)->after_loop();
}

/**
 * @brief Pcap::is_udp checks whether the packet is a UDP packet
 * @param pkt_data the packet to check
 * @return true if the packet is UDP
 */
template <typename PcapType> bool Pcap<PcapType>::is_udp(const uint8_t *pkt_data) {
  return pkt_data[ip_protocol_offset] == ip_protocol_udp;
}

/**
 * @brief Pcap::is_udp checks whether the packet is a TCP packet
 * @param pkt_data the packet to check
 * @return true if the packet is TCP
 */
template <typename PcapType> bool Pcap<PcapType>::is_tcp(const uint8_t *pkt_data) {
  return pkt_data[ip_protocol_offset] == ip_protocol_tcp;
}

/**
 * @brief Pcap::is_ipv4 checks whether the packet is an IPv4 packet
 * @param pkt_data the packet to check
 * @return true if packet is IPv4
 */
template <typename PcapType>
bool Pcap<PcapType>::is_ipv4(const uint8_t *pkt_data) {
  return hi_nibble(pkt_data[ethernet_frame_size]) == ip_version_v4;
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
template <typename PcapType>
bool Pcap<PcapType>::might_be_tox_dht(const uint8_t *pkt_data, uint32_t size) {
  if (!is_udp(pkt_data)) {
    return false;
  }

  size_t payload_length = size - get_udp_payload_offset(pkt_data);
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
template <typename PcapType>
typename Pcap<PcapType>::DhtPacketType
Pcap<PcapType>::get_dht_packet_type(const uint8_t *pkt_data) {
  uint8_t type = pkt_data[get_udp_payload_offset(pkt_data)];
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
template <typename PcapType>
const uint8_t *Pcap<PcapType>::get_dht_public_key(const uint8_t *) {
  return nullptr;
}

template <typename PcapType>
const uint8_t *Pcap<PcapType>::get_dht_nonce(const uint8_t *) {
  return nullptr;
}

/**
 * @brief Pcap::src_ip get the source IP of a packet
 * @param pkt_data the packet
 * @return the source IP of the packet
 */
template <typename PcapType>

std::string Pcap<PcapType>::src_ip(const uint8_t *pkt_data) {
  std::ostringstream s;
  for (int i = ip_src_offset; i < ip_src_offset + 4; i++) {
    s << (int)pkt_data[i];
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
template <typename PcapType> std::string Pcap<PcapType>::dst_ip(const uint8_t *pkt_data) {
  std::ostringstream s;
  for (int i = ip_dst_offset; i < ip_dst_offset + 4; i++) {
    s << (int)pkt_data[i];
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
template <typename PcapType>
uint8_t Pcap<PcapType>::get_udp_payload_offset(const uint8_t *pkt_data) {
  if (!is_udp(pkt_data)) {
    return 0;
  }
  uint8_t ihl = lo_nibble(pkt_data[ethernet_frame_size]);
  uint8_t ip_header_bits = ihl * 32;
  uint8_t ip_header_bytes = ip_header_bits / 8;

  return ethernet_frame_size + ip_header_bytes + udp_data_offset;
}


template class Pcap<TextPcap>;
template class Pcap<SqlitePcap>;
