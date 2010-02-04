#ifndef __DNS_NAT3_H__
#define __DNS_NAT3_H__

#ifndef _MSC_VER
  #include <stdint.h>
#endif

#include "dns_rr.h"

class DnsNAT3 : public DnsRR
{
  public:
    DnsNAT3();

    // returns true if there are two IPs and a port
    virtual bool rdata_valid();

    uint32_t ext_ip();
    void set_ext_ip(uint32_t);

    uint16_t ext_port();
    void set_ext_port(uint16_t);

    uint32_t int_ip();
    void set_int_ip(uint32_t);

  private:
    // a NAT3 record has two IPv4 addresses and a port
    static const size_t m_fixed_rdlen = 4 + 4 + 2;
};

#endif /* __DNS_A_H__ */
