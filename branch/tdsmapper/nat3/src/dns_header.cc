#include <cassert>
#include <vector>
#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#include "dns_header.h"
#include "types.h"
#include "functions.h"
#include <string.h>

#include <iostream>
#include <stdlib.h>

using namespace std;

#ifdef _MSC_VER
  #pragma pack(1)
  struct header_fmt
  {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
  };
#else
  struct header_fmt
  {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
  }__attribute__((__packed__));
#endif

DnsHeader::DnsHeader()
  : m_init(false)
{ 
  m_id = -1;
  m_qdcount = m_ancount = m_nscount = m_arcount = 0;

  memset(&m_flags, 0, sizeof(m_flags));
  m_flags.rd = 1;
}

DnsHeader::DnsHeader(bool question, int id)
{
  if (id < 0)
    m_id = (int)(65536 * (rand() / (RAND_MAX + 1.0)));
  else
    m_id = id;

  m_qdcount = m_ancount = m_nscount = m_arcount = 0;

  memset(&m_flags, 0, sizeof(m_flags));
  m_flags.response = !question;
  m_flags.rd = 1;
}

bool DnsHeader::response() 
{
  return m_flags.response;
}

rcode_t DnsHeader::rcode()
{
  return (rcode_t)m_flags.rcode;
}


bool DnsHeader::init(unsigned char *bytes, size_t size)
{
  if (size < SIZE)
  {
    m_init = false;
  }
  else
  {
    // read various shorts from the header
    header_fmt *h = (header_fmt *)bytes;
    m_id = ntohs(h->id);
    eprintf("Assigning an id of %d/%d\n", ntohs(h->id), m_id);
    m_qdcount = ntohs(h->qdcount);
    m_ancount = ntohs(h->ancount);
    m_nscount = ntohs(h->nscount);
    m_arcount = ntohs(h->arcount);
    eprintf("The details are %d,%d,%d,%d\n", m_qdcount, m_ancount, m_nscount, m_arcount);

    // copy the flags
    // this doesn't work with a bitfield struct :(
    // memcpy(&m_flags, bytes + 2, sizeof(m_flags));
    unpack_flags(bytes + 2);
    m_init = true;
  }
  eprintf("Assigning an id of %d/%d\n", m_id, id());
  return m_init;
}

void DnsHeader::to_wire(vector<u_char> &dest) {
    header_fmt h;

    h.id = htons(m_id);
    h.qdcount = htons(m_qdcount);
    h.ancount = htons(m_ancount);
    h.nscount = htons(m_nscount);
    h.arcount = htons(m_arcount);
    pack_flags((u_char *)&h.flags);

    for (unsigned i = 0; i < sizeof(h); ++i)
        dest.push_back(((u_char *)&h)[i]);
}

// the following are the only portable way of doing this stuff
void DnsHeader::unpack_flags(unsigned char *b)
{
  m_flags.response = b[0] & 0x80;
  m_flags.opcode = b[0] & 0x78;
  m_flags.aa = b[0] & 0x04;
  m_flags.tc = b[0] & 0x02;
  m_flags.rd = b[0] & 0x01;

  m_flags.ra = b[1] & 0x80;
  m_flags.z = b[1] & 0x60;
  m_flags.auth = b[1] & 0x10;
  m_flags.rcode = b[1] & 0x0f;
}

void DnsHeader::pack_flags(u_char *dest) {
  dest[0] = (m_flags.rd
          | (m_flags.tc << 1)
          | (m_flags.aa << 2)
          | (m_flags.opcode << 3)
          | (m_flags.response << 7));
    
  dest[1] = (m_flags.rcode
          | (m_flags.auth << 4)
          | (m_flags.z << 6)
          | (m_flags.ra << 7));
}
