#ifndef __DNS_QUERY_H__
#define __DNS_QUERY_H__

#ifndef _MSC_VER
  #include <netinet/in.h> /* for struct sockaddr_in */
#else
  #include <Winsock2.h>
#endif

#include "types.h"

class DnsPacket;
class DnsA;
class DnsNAT3;
class DnsName;
class TunnelMgr;

class DnsQuery {
  static struct sockaddr_in m_resolver;

  public:
    static void init(struct sockaddr_in &);

    DnsQuery(struct sockaddr_in &, DnsPacket &);
    ~DnsQuery();

    void add_response(DnsPacket &);
    bool done();

    DnsPacket &packet_to_forward();
    struct sockaddr_in &dest();

  private:
    DnsA *get_A_RR(DnsPacket &);
    DnsNAT3 *get_NAT3_RR(DnsPacket &);

    DnsPacket *nat3_query(DnsA &);
    DnsPacket *nat3_response(const DnsName &, uint32_t);

    uint32_t build_mapping(DnsNAT3 &);

    struct sockaddr_in m_src, m_dest;
    DnsPacket &m_packet, *m_fwd_packet, *m_original_err;
    bool m_done;

    TunnelMgr &m_mgr;
};

#endif /* __DNS_QUERY_H__ */
