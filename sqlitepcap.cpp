#include <iostream>

#include "sqlitepcap.h"

SqlitePcap::SqlitePcap(const char *filename, const char *_database_filename)
    : Pcap::Pcap(filename) {
  database_filename = _database_filename;
}

void SqlitePcap::loop() {
  std::cout << "Not yet implemented" << std::endl;
  return;
}

void SqlitePcap::packet_handler(uint32_t, uint32_t, uint32_t, const uint8_t *) {
}
