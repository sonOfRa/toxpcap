#ifndef SQLITEPCAP_H
#define SQLITEPCAP_H

#include "pcap.h"

class SqlitePcap : public Pcap<SqlitePcap> {
public:
  SqlitePcap(const char *, const char *);
  void before_loop();
  void after_loop();
  void packet_handler(uint32_t, uint32_t, uint32_t, const uint8_t *);

private:
  const char *database_filename;
};

#endif // SQLITEPCAP_H
