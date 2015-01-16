#include <iostream>
#include <stdexcept>

#include "pcap.h"
#include "textpcap.h"
#include "sqlitepcap.h"

/**
 * Writes tox packets to an sqlite database or standard output.
 *
 * For now, only UDP4 packets are parsed. The amount of IPv6 traffic is
 * currently negligible to gather meaningful data. Since we haven't specified
 * any of the TCP packets yet, we cannot collect meaningful data on them. TCP
 * packets are also ignored.
 */
int main(int argc, char *argv[]) {
  if (argc < 2 || argc > 3) {
    std::cerr << "Invocation: " << argv[0] << " dump.pcap <database.sqlite>"
              << std::endl;
    std::cerr << "Exiting." << std::endl;
    exit(EXIT_FAILURE);
  }

  Pcap *pc;
  try {
    if (argc == 2) {
      // No Sqlite database path supplied, run in text mode
      pc = new TextPcap(argv[1]);
    } else {
      // Run in Sqlite mode
      pc = new SqlitePcap(argv[1], argv[2]);
    }
  } catch (std::runtime_error &e) {
    std::cerr << "Could not start pcap parsing: " << e.what() << std::endl;
    exit(EXIT_FAILURE);
  }
  pc->loop();
  delete pc;
}
