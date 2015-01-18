#ifndef SQLITEPCAP_H
#define SQLITEPCAP_H

#include "pcap.h"

class SqlitePcap : public Pcap {
public:
  SqlitePcap(const char *, const char *);
  void loop();
  void packet_handler(uint32_t, uint32_t, uint32_t, const uint8_t *);

private:
  const char *database_filename;
};

#endif // SQLITEPCAP_H
