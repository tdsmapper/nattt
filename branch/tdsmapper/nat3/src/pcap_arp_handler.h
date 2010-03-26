#ifndef __PCAP_ARP_HANDLER_
#define __PCAP_ARP_HANDLER_

#include "types.h"
#include <pcap.h>
#define ADAPTERBUFSIZE 256

class PcapArpHandler
{
private:
  char m_szAdapterName[ADAPTERBUFSIZE];

  uint32_t m_uInterfaceIP;
  uint32_t m_uTuntapMask;
  uint32_t m_uTuntapNet;

  bool setPcapFilter();
public:
  bool Init(uint32_t &p_uTuntapAddress, uint32_t &p_uTuntapMask);
  bool QueryAdapterDetails(uint32_t &ip);
  void Start();
};

void pcap_arp_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif /* __PCAP_ARP_HANDLER_ */
