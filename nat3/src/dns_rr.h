#ifndef __DNS_DnsRR_H__
#define __DNS_DnsRR_H__

#include <cassert>
#include <vector>

#include <sys/types.h>
#include "types.h"
#include "functions.h"

typedef unsigned char u_char;

#define DNS_RR_A                1
#define DNS_RR_NAT3         65324

class DnsName;
class DnsCompression;

class DnsRR
{
  public:
    DnsRR(int);
    virtual ~DnsRR();

    static DnsRR &question(const DnsName &, int);

    void init(DnsName *, int);
    void init(DnsName *, int, int, size_t, u_char *);

    // returns DnsRR pointer if DnsRR is correctly parsed, NULL otherwise
    static DnsRR *parse(u_char *, size_t, size_t &);
    static DnsRR *parse(u_char *, size_t, size_t &, bool);

    inline uint16_t type(void) { return m_type; }
    inline const DnsName &name(void) { return *m_name; }

    // overridden by children, returns true iff the RDATA is valid format
    virtual bool rdata_valid();

    // converts the DnsRR to wire format
    void to_wire(std::vector<u_char> &, DnsCompression &);
    virtual void rdata_to_wire(std::vector<u_char> &, DnsCompression &);

    // set the RDATA, copying it for you
    void set_rdata(u_char *, size_t);

  private:
    // static factory method for build DnsRR based on type
    static DnsRR &factory(int);

    // helper functions for parsing the various DnsRR types
    static DnsRR *parse_question_rr(u_char *, size_t, size_t &, DnsName *);
    static DnsRR *parse_normal_rr(u_char *, size_t, size_t &, DnsName *);

    // converts the name to DNS wire representation
    bool name_to_bytes(u_char *, size_t &);

    bool m_init;

    DnsName *m_name;
    uint16_t m_type, m_class;
    int32_t m_ttl;

  protected:
    size_t m_rdlen;
    u_char *m_rdata;
};

#endif /* __DnsRR_H__ */
