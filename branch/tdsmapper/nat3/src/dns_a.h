#ifndef __DNS_A_H__
#define __DNS_A_H__

/* No need to include anything for Windows. Types defined in types.h */
#ifndef _MSC_VER
  #include <stdint.h>
#endif

#include "dns_rr.h"

class DnsName;

class DnsA : public DnsRR
{
  public:
    DnsA();
    DnsA(const DnsName &, uint32_t);

    // returns true if there are four bytes of RDATA
    virtual bool rdata_valid();

    // A's RDATA is an IP address
    uint32_t ip();
    void set_ip(uint32_t);
};

#endif /* __DNS_A_H__ */
