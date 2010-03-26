
#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#include "dns_nat3.h"
#include "dns_rr.h"
#include "types.h"
#include "log.h"
#include "functions.h"

#define GOOD assert(m_rdlen == m_fixed_rdlen)
#define LONG(X) *(uint32_t *)(m_rdata + (X))
#define SHORT(X) *(uint16_t *)(m_rdata + (X))

DnsNAT3::DnsNAT3()
  : DnsRR(DNS_RR_NAT3)
{
}

bool DnsNAT3::rdata_valid()
{
  return m_rdlen == m_fixed_rdlen;
}

uint32_t DnsNAT3::ext_ip()
{
  GOOD;
  uint32_t ip = LONG(0);
  return ntohl(ip);
}

void DnsNAT3::set_ext_ip(uint32_t ip)
{
  GOOD;
  LONG(0) = ip;
}

uint16_t DnsNAT3::ext_port()
{
  GOOD;
  uint16_t port = SHORT(4);
  return ntohs(port);
}

void DnsNAT3::set_ext_port(uint16_t port)
{
  GOOD;
  SHORT(4) = htons(port);
}

uint32_t DnsNAT3::int_ip()
{
  GOOD;
  uint32_t ip = LONG(6);
  return ntohl(ip);
}

void DnsNAT3::set_int_ip(uint32_t ip)
{
  GOOD;
  LONG(6) = ip;
}
