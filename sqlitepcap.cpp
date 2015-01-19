#include <iostream>

#include "sqlitepcap.h"
SqlitePcap::SqlitePcap(const char *filename, const char *_database_filename)
    : Pcap::Pcap(filename) {
  database_filename = _database_filename;
}

void SqlitePcap::before_loop() {

}

void SqlitePcap::after_loop() {

}

void SqlitePcap::packet_handler(time_t, uint32_t, uint32_t, const uint8_t *) {
}
