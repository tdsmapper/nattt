#ifndef __DNS_HEADER_H__
#define __DNS_HEADER_H__
#include "datatypes.h"
enum rcode_t
{
    DNS_NOERROR = 0, DNS_FORMERR, DNS_SERVFAIL, DNS_NXDOMAIN, DNS_NOTIMP,
    DNS_REFUSED, DNS_YXDOMAIN, DNS_YXRRSET, DNS_NXRRSET, DNS_NOTAUTH,
    DNS_NOTZONE, DNS_BADSIG, DNS_BADKEY, DNS_BADTIME
};

class DnsHeader
{
  public:
    DnsHeader();
    DnsHeader(bool, int);
    bool init(unsigned char *bytes, size_t size);

    // size of a DNS header (constant)
    static const size_t SIZE = 12;

    inline int id() { return m_id; }
    inline int qd_count() { return m_qdcount; }
    inline int an_count() { return m_ancount; }
    inline int ns_count() { return m_nscount; } 
    inline int ar_count() { return m_arcount; }

    bool response();
    rcode_t rcode();

    void to_wire(std::vector<u_char> &);

    inline void qd_inc() { ++m_qdcount; }
    inline void an_inc() { ++m_ancount; }

  private:
    bool m_init;

    int m_id, m_qdcount, // Question
      m_ancount,         // Answer
      m_nscount,         // Authoritative NS
      m_arcount;         // Additional records
    struct {
      bool response;
      unsigned opcode;
      bool aa;
      bool tc;
      bool rd;
      bool ra;
      unsigned z;
      bool auth;
      unsigned rcode;
    } m_flags;

    void unpack_flags(unsigned char *);
    void pack_flags(unsigned char *);
};

#endif /* __DNS_HEADER_H__ */
