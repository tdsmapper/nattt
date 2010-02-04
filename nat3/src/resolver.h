#ifndef _RESOLVER_H
#define _RESOLVER_H

#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <netinet/in.h>
#endif

#include <deque>
#include <string>
#include <sys/types.h>
#include "types.h"


#include "dns_query.h"
#include "lru_cache.h"

typedef int PLACE_HOLDER_t;
typedef unsigned char u_char;

#define DNS_PORT 53
class DnsPacket;
class DnsA;
class TunnelEntry;

#define SOCK_PATH "/tmp/nat3.sock"
#define SOCK_MAGIC 0x1337cafe

struct queue_ent {
    struct sockaddr_in dst;
    u_char *bytes;
    size_t len;
};

class Resolver
{
  // Member Variables
  private:
    struct sockaddr_in m_tRes;
    uint32_t m_tResIP;
    uint16_t m_tPort;
    LruCache<std::string, TunnelEntry *> m_oReqCache;

  // Methods
  public:
    Resolver();
    virtual ~Resolver();

    bool init(uint32_t p_tResIP,
              uint16_t p_tPort);

    bool listen();

    uint32_t lookup(std::string p_sName);
    TunnelEntry &getMapping(TunnelEntry &p_oCandidateEnt);

  private:
    void select_loop(void);

    void read_loop(void);
    void read_packet(struct sockaddr_in &, DnsPacket &);

    void write_loop(void);
    void write_packet(struct sockaddr_in &, DnsPacket &);
    void write_packet(struct sockaddr_in &, u_char *, size_t);

    // helpers to the above three functions
    bool try_send(struct sockaddr_in &, u_char *, size_t);
    void enqueue(struct sockaddr_in &, u_char *, size_t);

#ifdef _MSC_VER 
    bool create_unix_socket(void);
    void read_unix_socket(void);
    void set_nonblocking(int);
#endif /* _MSC_VER */

    SOCKET m_udp_fd, m_unix_fd;
    LruCache<int, DnsQuery> m_queries;

    deque<struct queue_ent> m_send_q;
};

#endif
