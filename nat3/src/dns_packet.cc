#include <vector>
#include <algorithm>

using namespace std;

#include "dns_packet.h"
#include "dns_compression.h"
#include "dns_header.h"
#include "dns_rr.h"

// default param for size is 512
DnsPacket::DnsPacket(int size)
  : m_parsed(false),
    m_header(NULL)
{
  m_bytes.reserve(size);
}

DnsPacket::DnsPacket(bool question, int id)
  : m_parsed(false)
{
  m_header = new DnsHeader(question, id);
}

DnsPacket::~DnsPacket()
{
  if (m_header != NULL)
  {
    delete m_header;
  }
  clear_vectors();
}

void DnsPacket::add_bytes(unsigned char *bytes, size_t count)
{
  // there has to be a better way
  for (size_t i = 0; i < count; ++i)
  {
    m_bytes.push_back(bytes[i]);
  }
}

// serialise the packet into a vector
void DnsPacket::to_wire(vector<u_char> &dest) {
    dest.clear();
    DnsCompression c;

    m_header->to_wire(dest);

    /* questions */
    for (size_t i = 0; i < m_qd.size(); ++i)
        m_qd[i]->to_wire(dest, c);

    /* answers */
    for (size_t i = 0; i < m_an.size(); ++i)
        m_an[i]->to_wire(dest, c);

    /* ns */
    for (size_t i = 0; i < m_ns.size(); ++i)
        m_ns[i]->to_wire(dest, c);

    /* additional */
    for (size_t i = 0; i < m_ar.size(); ++i)
        m_ar[i]->to_wire(dest, c);
}

u_char *DnsPacket::get_bytes(size_t &size) {
    vector<u_char> v;
    to_wire(v);

    size = v.size();
    u_char *ret = new u_char[size];
    copy(v.begin(), v.end(), ret);

    return ret;
}

// parse the packet and see if it's legtimiate
bool DnsPacket::parse()
{
  // no longer need a vector
  size_t size = m_bytes.size();
  unsigned char *bytes = new u_char[m_bytes.size()];
  copy(m_bytes.begin(), m_bytes.end(), bytes);

  bool ok = true;

  m_header = new DnsHeader();
  if (m_header->init(bytes, size))
  {
    size_t pos = DnsHeader::SIZE;

    // get all the question RRs
    for (int i = 0; ok && i < m_header->qd_count(); ++i)
    {
      DnsRR *new_rr = DnsRR::parse(bytes, size, pos, true);
      if (new_rr != NULL)
        m_qd.push_back(new_rr);
      else
        ok = false;
    }

    // get the answers
    for (int i = 0; ok && i < m_header->an_count(); ++i)
    {
      DnsRR *new_rr = DnsRR::parse(bytes, size, pos);
      if (new_rr != NULL)
        m_an.push_back(new_rr);
      else
        ok = false;
    }

    // get the authoritative NSes
    for (int i = 0; ok && i < m_header->ns_count(); ++i)
    {
      DnsRR *new_rr = DnsRR::parse(bytes, size, pos);
      if (new_rr != NULL)
        m_ns.push_back(new_rr);
      else
        ok = false;
    }

    // finally, get the additional RRs
    for (int i = 0; ok && i < m_header->ar_count(); ++i)
    {
      DnsRR *new_rr = DnsRR::parse(bytes, size, pos);
      if (new_rr != NULL)
        m_ar.push_back(new_rr);
      else
        ok = false;
    }

    if (pos != size)
      ; // XXX perhaps generate a warning about extraneous data?

    if (ok)
      m_parsed = true;
  }
  else
  {
    m_parsed = false;
  }

  if (!ok) {
    clear_vectors();
    m_parsed = false;
  }

  return m_parsed;
}

const vector<DnsRR *> &DnsPacket::questions(void)
{
  return m_qd;
}

const vector<DnsRR *> &DnsPacket::answers(void)
{
  return m_an;
}

#if 0
const vector<DnsRR *> &DnsPacket::nses(void)
{
  return m_ns;
}

const vector<DnsRR *> &DnsPacket::additional(void)
{
  return m_ar;
}
#endif

void DnsPacket::add_question(DnsRR &q)
{
  m_qd.push_back(&q);
  m_header->qd_inc();
}

void DnsPacket::add_answer(DnsRR &a)
{
  m_an.push_back(&a);
  m_header->an_inc();
}

void DnsPacket::clear_vectors()
{
  vector<DnsRR *>::iterator iter;

  for (iter = m_qd.begin(); iter != m_qd.end(); ++iter)
    delete *iter;
  m_qd.clear();

  for (iter = m_an.begin(); iter != m_an.end(); ++iter)
    delete *iter;
  m_an.clear();

  for (iter = m_ns.begin(); iter != m_ns.end(); ++iter)
    delete *iter;
  m_ns.clear();

  for (iter = m_ar.begin(); iter != m_ar.end(); ++iter)
    delete *iter;
  m_ar.clear();
}
