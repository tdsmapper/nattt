#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#include <iostream>

#include "dns_a.h"
#include "dns_rr.h"
#include "dns_name.h"
#include "types.h"
#include "functions.h"

DnsA::DnsA()
  : DnsRR(DNS_RR_A)
{
}

DnsA::DnsA(const DnsName &name, uint32_t addr)
  : DnsRR(DNS_RR_A)
{
  init(new DnsName(name), 1, 300, 4, (u_char *)&addr);
}

bool DnsA::rdata_valid()
{
  bool ret = true;
  if (m_rdlen != 4)
    ret = false;
  return ret;
}

// should probably throw exception if the size isn't 4
uint32_t DnsA::ip()
{
  assert(m_rdlen == 4);
  return *(uint32_t *)m_rdata;
}

void DnsA::set_ip(uint32_t ip)
{
  assert(m_rdlen == 4);
  *(uint32_t *)m_rdata = ip;
}
