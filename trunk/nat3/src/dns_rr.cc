#include <cassert>
#include <cstring>
#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#include "dns_rr.h"
#include "dns_a.h"
#include "dns_name.h"
#include "types.h"
#include "functions.h"

#ifdef DEBUG
#include <iostream>
#endif

#define the_force namespace std
using the_force;

#ifdef _MSC_VER
  #pragma pack(1)
  struct q_header
  {
    int16_t type;
    int16_t qclass;
  };

  #pragma pack(1)
  struct rr_header
  {
    q_header q;
    int32_t ttl;
    uint16_t rdlen;
  };
#else
  struct q_header
  {
    int16_t type;
    int16_t qclass;
  } __attribute__((__packed__));

  struct rr_header
  {
    q_header q;
    int32_t ttl;
    uint16_t rdlen;
  } __attribute__((__packed__));
#endif

DnsRR::DnsRR(int type)
  : m_init(false),
    m_name(NULL),
    m_type(type),
    m_rdlen(0),
    m_rdata(NULL)
{
}

DnsRR::~DnsRR()
{
  if (m_name != NULL)
    delete m_name;
  if (m_rdlen != 0 && m_rdata != NULL)
    delete [] m_rdata;
}

// generate a question from a name and type
DnsRR &DnsRR::question(const DnsName &name, int type)
{
  DnsRR *ret = new DnsRR(type);
  ret->init(new DnsName(name), 1);
  return *ret;
}

// for initialising question RRs
void DnsRR::init(DnsName *name, int i_class)
{
  init(name, i_class, -1, 0, NULL);
}

// for initialising normal RRs
void DnsRR::init(DnsName *name, int i_class, int ttl, size_t rdlen,
        u_char *rdata)
{
  // if it's already been initialised, we need to delete some crap
  if (m_init)
  {
    if (m_name != NULL)
      delete m_name;
    if (m_rdlen != 0 && m_rdata != NULL)
      delete [] m_rdata;
  }

  m_name = name;
  m_class = i_class;
  m_ttl = ttl;

  set_rdata(rdata, rdlen);

  m_init = true;
}

// method for parsing non-question DnsRRs
DnsRR *DnsRR::parse(u_char *bytes, size_t size, size_t &offset)
{
  return parse(bytes, size, offset, false);
}

// a factory method for parsing DnsRRs in wire format
DnsRR *DnsRR::parse(u_char *bytes, size_t size, size_t &offset, bool question)
{
  DnsRR *ret = NULL;
  DnsName *name = NULL;

  // attempt to read the name
  if ((name = DnsName::from_wire(bytes, size, offset)) != NULL)
  {
    // if it's a question we only need four more bytes
    if (question)
    {
      ret = parse_question_rr(bytes, size, offset, name);
    }

    // if it's not a question, we have to read a variable amount of data
    else
    {
      ret = parse_normal_rr(bytes, size, offset, name);
    }
  }

  // clean up memory we may have allocated if there was a problem
  if (ret == NULL && name != NULL)
  {
    delete name;
  }

  return ret;
}

DnsRR *DnsRR::parse_question_rr(u_char *bytes, size_t size, size_t &offset,
        DnsName *n)
{
  DnsRR *ret = NULL;
  if (offset + sizeof(q_header) <= size)
  {
    q_header *q = (q_header *)(bytes + offset);
    int type = htons(q->type);
    int qclass = htons(q->qclass);
    offset += sizeof(q_header);

    DnsRR &new_rr = factory(type);
    new_rr.init(n, qclass);
    ret = &new_rr;
  }
  return ret;
}

DnsRR *DnsRR::parse_normal_rr(u_char *bytes, size_t size, size_t &offset,
        DnsName *n)
{
  DnsRR *ret = NULL;
  u_char *rdata = NULL;

  // 10 bytes of fixed data
  if (offset + sizeof(rr_header) <= size)
  {
    rr_header *r = (rr_header *)(bytes + offset);
    int type = ntohs(r->q.type);
    int qclass = ntohs(r->q.qclass);
    int rdlen = ntohs(r->rdlen);

    // ntohl returns unsigned, and we want signed
    uint32_t u_ttl = ntohl(r->ttl);
    int ttl = *(int *)&u_ttl;

    // try to get the rdata
    if (offset + sizeof(rr_header) + rdlen <= size)
    {
      // no need to allocate memory for 0-length RDATA
      if (rdlen > 0)
      {
        rdata = new u_char[rdlen];
        memcpy(rdata, bytes + offset + 10, rdlen);
      }
      offset += sizeof(rr_header) + rdlen;

      DnsRR &new_rr = factory(type);
      new_rr.init(n, qclass, ttl, rdlen, rdata);
      ret = &new_rr;

      // make sure its RDATA isn't bogus
      /* we're dumb, so let's be dumb
      if (!new_rr.rdata_valid())
      {
        delete ret;
        ret = NULL;
      }
      */
    }
  }

  if (ret == NULL && rdata != NULL)
  {
    delete [] rdata;
  }

  return ret;
}

bool DnsRR::rdata_valid()
{
  bool ret = true;

  if (m_rdlen > 0 && m_rdata == NULL)
    ret = false;

  return ret;
}

void DnsRR::to_wire(vector<u_char> &dest, DnsCompression &compression)
{
  // copy the name in
  m_name->to_wire(dest, compression);

  // question RR
  if (m_ttl < 0)
  {
    q_header q;
    q.type = htons(m_type);
    q.qclass = htons(m_class);

    for (unsigned i = 0; i < sizeof(q); ++i)
      dest.push_back(((u_char *)&q)[i]);
  }

  // normal RR
  else
  {
    rr_header r;
    uint32_t u_ttl = *(uint32_t *)&m_ttl;

    r.q.type = htons(m_type);
    r.q.qclass = htons(m_class);
    r.ttl = htonl(u_ttl);

    // - 2, because we copy the rdlen in the virtual rdata_to_wire
    for (unsigned i = 0; i < sizeof(r) - 2; ++i)
      dest.push_back(((u_char *)&r)[i]);

    rdata_to_wire(dest, compression);
  }
}

void DnsRR::rdata_to_wire(vector<u_char> &dest, DnsCompression &compression)
{
  dest.push_back((m_rdlen >> 8) & 0xff);
  dest.push_back(m_rdlen & 0xff);

  for (unsigned i = 0; i < m_rdlen; ++i)
    dest.push_back(m_rdata[i]);
}

void DnsRR::set_rdata(u_char *data, size_t len)
{
  if (m_rdata != NULL)
    delete [] m_rdata;

  m_rdlen = len;
  if (len > 0)
  {
    m_rdata = new u_char[len];
    memcpy(m_rdata, data, len);
  }
  else
    m_rdata = NULL;
}

// private methods below

// builds an DnsRR of the specified type
DnsRR &DnsRR::factory(int type)
{
  DnsRR *ret;

  switch (type)
  {
    case DNS_RR_A:
      ret = new DnsA();
      break;
    default:
      ret = new DnsRR(type);
  }

  return *ret;
}
