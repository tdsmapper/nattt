#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <err.h>
    #include <arpa/inet.h>
  #include <sys/un.h>
#endif

#include <fcntl.h>
#include <errno.h>

#include <cstdio>
#include <string>

#include "resolver.h"
#include "tun_ent.h"
#include <stdlib.h>

#include "dns_packet.h"
#include "dns_header.h"
#include "dns_rr.h"

#include "lru_cache.h"
#include "types.h"
#include "functions.h"

using namespace std;

Resolver::Resolver()
  : m_tResIP(0),
    m_tPort(0)
{
  m_tRes.sin_addr.s_addr = 0;
  m_tRes.sin_port = htons(DNS_PORT);
  m_tRes.sin_family = AF_INET;
}

Resolver::~Resolver()
{
  unlink(SOCK_PATH);
}

bool Resolver::init(uint32_t p_tResIP,
                    uint16_t p_tPort)
{
  m_tResIP = htonl(p_tResIP);
  m_tPort = htons(p_tPort);

  m_tRes.sin_addr.s_addr = m_tResIP;
  m_tRes.sin_port = m_tPort;
  m_tRes.sin_family = AF_INET;

  DnsQuery::init(m_tRes);
  
  return true;
}

bool Resolver::listen()
{
  /* UNIX socket */
#ifndef _MSC_VER
  if (!create_unix_socket())
    return false;
#else
  m_unix_fd = -1;
#endif

  // create the socket
  m_udp_fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (m_udp_fd >= 0)
  {
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(DNS_PORT);

    // allow the socket to re-bind to the same port
    do {
      int ignore = 0;
      if (setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&ignore,
            sizeof(ignore)) < 0)
      {
        fprintf(stderr, "setsockopt with SO_REUSEADDR failed with error %d\n", GetLastError());
        return false;
      }
    }
    while(0);

    // Windows non-blocking is done at create
#ifndef _MSC_VER
    set_nonblocking(m_udp_fd);
#endif /* _MSC_VER */

    // bind to the port
    if (bind(m_udp_fd, (struct sockaddr *)&sin, sizeof(sin)) == 0)
    {
      eprintf("PANZER: port %d\n", sin.sin_port);  
      select_loop();
      // this can fall through
    }
  }

  return false;
}

void Resolver::select_loop(void)
{
  fd_set rfd, wfd, efd;

  do {
    /* Select loop: Add the UDP fds to read and write. Add Unix FDs only for UNIX */
    FD_ZERO(&rfd);
    FD_SET(m_udp_fd, &rfd);
    FD_ZERO(&efd);
    FD_SET(m_udp_fd, &efd);
#ifndef _MSC_VER
    FD_SET(m_unix_fd, &rfd);
    FD_SET(m_unix_fd, &efd);
#endif

    // only care about writing if the send queue has stuff in it
    FD_ZERO(&wfd);
    if (!m_send_q.empty())
    {
      FD_SET(m_udp_fd, &wfd);
    }

    /* On Windows, the first parameter to select is ignored. So we can let it use m_udf_fd */
    if (select(m_udp_fd + 1, &rfd, &wfd, &efd, NULL) < 0) // Is the udp fd always higher?
    {
      err(1, "select");
      eprintf("Last error was %d\n", GetLastError());
    }

    if (FD_ISSET(m_udp_fd, &efd))
    {
      printf("error on the socket\n");
      exit(1);
    }

    if (FD_ISSET(m_udp_fd, &wfd))
    {
      write_loop();
    }

    if (FD_ISSET(m_udp_fd, &rfd))
    {
      read_loop();
    }

    /* Unix socket works only on Unix (Surprise!) */
#ifndef _MSC_VER
    if (FD_ISSET(m_unix_fd, &efd))
    {
      printf("error on unix socket\n");
      exit(1);
    }

    if (FD_ISSET(m_unix_fd, &rfd))
    {
      read_unix_socket();
    }
#endif
  } while(true);
}

// try to empty the queue
void Resolver::write_loop(void)
{
  bool sent = false;
  do {
    struct queue_ent next = m_send_q.front();
    sent = try_send(next.dst, next.bytes, next.len);
    if (sent)
    {
      m_send_q.pop_front();
      delete [] next.bytes;
    }
  }
  while (sent && !m_send_q.empty());
}

void Resolver::read_loop(void)
{
  SSIZE_T r;
  struct sockaddr_in sin;
  socklen_t sz;

  u_char buf[512];

  do
  {
    sz = sizeof(sin);
    if ((r = recvfrom(m_udp_fd, (char*)buf, sizeof(buf), 0,
            (struct sockaddr *)&sin, &sz)) > 0)
    {
      DnsPacket *p ;
      p = new DnsPacket(r);
      p->add_bytes(buf, r);
      if (p->parse())
      {
        read_packet(sin, *p);
      }
      else
      {
        delete p;
      }
    }
  }
  while (r > 0 || errno == EINTR);

  if (r == 0)
  {
    printf("socket closed while reading\n");
    exit(1);
  }

  if (r < 0 && errno != EAGAIN)
  {
    printf("fatal error on socket during read: %s\n", strerror(errno));
    exit(1);
  }
}

void Resolver::read_packet(struct sockaddr_in &from, DnsPacket &p)
{
  DnsHeader& h = p.header();
  // response packet
  if (h.response())
  {
    int id = h.id();
    DnsQuery *q = m_queries.get(id);
    if (q == NULL)
    {
      delete &p;
    }
    else
    {
      q->add_response(p);
      sleep(1);
      // forward packet
      write_packet(q->dest(), q->packet_to_forward());

      if (q->done())
      {
        int id = h.id();
        m_queries.remove(id);
      }
    }
  }

  // packet is a question
  else
  {
    // silently drop packets that aren't from localhost
    if (from.sin_addr.s_addr == ntohl(INADDR_LOOPBACK))
    {
      DnsQuery *q = new DnsQuery(from, p);

      // add the query to the LRU
      int id = p.header().id();
      m_queries.add(id, *q);

      size_t len;
      u_char *b = p.get_bytes(len);
      write_packet(m_tRes, b, len);
    }
    else
    {
      delete &p;
    }
  }
}

uint32_t Resolver::lookup(std::string p_sName)
{
  return 0;
}

TunnelEntry &Resolver::getMapping(TunnelEntry &p_oCandidateEnt)
{
  // Placeholder so it compiles
  TunnelEntry *pEnt = new TunnelEntry();
  return *pEnt;
}

void Resolver::write_packet(struct sockaddr_in &dst, DnsPacket &p)
{
  size_t size;
  u_char *bytes = p.get_bytes(size);
  write_packet(dst, bytes, size);
}

void Resolver::write_packet(struct sockaddr_in &dst, u_char *b, size_t len)
{
  bool sent = false;
  //printf("trying to send to %x:%d\n", dst.sin_addr.s_addr, ntohs(dst.sin_port));

  // attempt to write the packet if the queue is empty
  if (m_send_q.empty())
  {
    sent = try_send(dst, b, len);
  }

  if (!sent)
  {
    enqueue(dst, b, len);
  }
}

bool Resolver::try_send(struct sockaddr_in &dst, u_char *b, size_t len)
{
  SSIZE_T w;
  do
  {
    w = sendto(m_udp_fd, (char*)b, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (w > 0)
    {
      eprintf("sent to %x:%d\n", dst.sin_addr.s_addr, ntohs(dst.sin_port));
      delete [] b;
    }
  }
  while (w < 0 && errno == EINTR);

  if (w == 0)
  {
    eprintf("socket closed while writing\n");
    exit(1);
  }
  if (w < 0 && errno != EAGAIN)
  {
    int errorNum = GetLastError();
    eprintf("error on socket while writing: %s/%d\n", strerror(errorNum), errorNum);
    exit(1);
  }

  // return true only if we wrote the packet
  if (w > 0)
  {
    return true;
  }
  return false;
}

void Resolver::enqueue(struct sockaddr_in &dst, u_char *b, size_t len)
{
  struct queue_ent e = { dst, b, len };
  m_send_q.push_back(e);
}

#ifndef _MSC_VER

bool Resolver::create_unix_socket(void)
{
  m_unix_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (m_unix_fd < 0) {
    printf("Cannot create unix socket: %s\n", strerror(errno));
    return false;
  }

  unlink(SOCK_PATH);

  struct sockaddr_un sun;
  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, SOCK_PATH);

  if (bind(m_unix_fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
    printf("Cannot bind to unix socket: %s\n", strerror(errno));
    close(m_unix_fd);
    return false;
  }

  set_nonblocking(m_unix_fd);

  return true;
}
#endif /* _MSC_VER */

#ifndef _MSC_VER
void Resolver::read_unix_socket(void)
{
  u_char buf[9];
  SSIZE_T r;

  do {
    r = recv(m_unix_fd, buf, sizeof(buf), 0);
    if (r == 8) {
      uint32_t *ptr = (uint32_t*)buf;
      uint32_t magic = ntohl(*ptr);
      if (magic == SOCK_MAGIC)
        m_tRes.sin_addr.s_addr = *(uint32_t *)(buf + 4);
    }
  } while (r > 0 || (r < 0 && errno == EINTR));

  if (r < 0 && errno != EAGAIN)
    err(1, "recv");

  if (r == 0) {
    printf("unix socket closed\n");
    exit(1);
  }
}

#endif /* _MSC_VER */

#ifndef _MSC_VER
void Resolver::set_nonblocking(int fd) {
  long flags;
  
  if ((flags = fcntl(fd, F_GETFL)) < 0)
    err(1, "fcntl(F_GETFL)");
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    err(1, "fcntl(F_SETFL)");
}
#endif
