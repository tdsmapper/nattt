#include <vector>

#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
#endif

using namespace std;

#include "dns_query.h"
#include "dns_header.h"
#include "dns_packet.h"
#include "dns_rr.h"
#include "dns_a.h"
#include "dns_nat3.h"
#include "dns_name.h"
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include "tun_mgr.h"
#include "tun_ent.h"
#include "types.h"
#include "functions.h"

struct sockaddr_in DnsQuery::m_resolver;

void DnsQuery::init(struct sockaddr_in &resolver)
{
  DnsQuery::m_resolver = resolver;
}

DnsQuery::DnsQuery(struct sockaddr_in &sin, DnsPacket &p)
  : m_src(sin),
    m_dest(sin),
    m_packet(p),
    m_fwd_packet(NULL),
    m_original_err(NULL),
    m_done(false),
    m_mgr(TunnelMgr::getInstance())
{
}

DnsQuery::~DnsQuery()
{
  delete &m_packet;

  if (m_original_err != NULL && m_original_err != m_fwd_packet)
    delete m_original_err;

  if (m_fwd_packet != NULL)
    delete m_fwd_packet;
}

void DnsQuery::add_response(DnsPacket &p)
{
  DnsHeader &h = p.header();

  // forward along NOERROR packets
  // Some DNS server implementations return a NOERROR for a subdomain if they are the auth domain holder.
  // Therefore, also check out the answer count is greater than zero.
  if ((h.rcode() == DNS_NOERROR) && (h.an_count() > 0))
  {
    DnsNAT3 *nat3_rr;

    if ((nat3_rr = get_NAT3_RR(p)) != NULL)
    {
      uint32_t mapping = build_mapping(*nat3_rr);
      m_fwd_packet = nat3_response(nat3_rr->name(), mapping);
    }
    else
      m_fwd_packet = &p;

    m_dest = m_src;
    m_done = true;
  }

  // otherwise we may have to do something special
  else
  {
    DnsA *a_rr;
  
    // if we get an A back with an error, want to try to find N3
    // There exists an "A" record
    if ((a_rr = get_A_RR(p)) != NULL)
    {
      m_original_err = &p;
      m_fwd_packet = nat3_query(*a_rr);
      m_dest = DnsQuery::m_resolver;
    }
    else
    {
      // if we stored an error, forward that along
      if (m_original_err != NULL)
        m_fwd_packet = m_original_err;
      else
        m_fwd_packet = &p;

      m_dest = m_src;
      m_done = true;
    }
  }
}

DnsPacket &DnsQuery::packet_to_forward()
{
  return *m_fwd_packet;
}

struct sockaddr_in &DnsQuery::dest()
{
  return m_dest;
}

bool DnsQuery::done()
{
  return m_done;
}

DnsA *DnsQuery::get_A_RR(DnsPacket &p)
{
  DnsA *ret = NULL;

  if (p.header().qd_count() >= 1)
  {
    vector<DnsRR *> questions = p.questions();
    if (questions[0]->type() == DNS_RR_A)
    {
      ret = (DnsA *)questions[0];
    }
  }

  return ret;
}

DnsNAT3 *DnsQuery::get_NAT3_RR(DnsPacket &p)
{
  if (p.header().an_count() >= 1)
  {
    vector<DnsRR *> answers = p.answers();
    if (answers[0]->type() == DNS_RR_NAT3)
    {
      return (DnsNAT3 *)answers[0];
    }
  }

  return NULL;
}

DnsPacket *DnsQuery::nat3_query(DnsA &a)
{
  DnsRR &q = DnsRR::question(a.name(), DNS_RR_NAT3);

  DnsPacket *ret = new DnsPacket(true, m_packet.header().id());
  ret->add_question(q);

  return ret;
}

DnsPacket *DnsQuery::nat3_response(const DnsName &name, uint32_t mapping)
{
  DnsPacket *ret = new DnsPacket(false, m_packet.header().id());
  DnsA *a = new DnsA(name, htonl(mapping));

  ret->add_question(DnsRR::question(name, DNS_RR_A));
  ret->add_answer(*a);

  return ret;
}

uint32_t DnsQuery::build_mapping(DnsNAT3 &n)
{
  tun_hdr_t header;
  TunnelEntry entry;
  string key;

  memset(&header, 0, sizeof(header));
  header.m_uRemoteIP = n.ext_ip();
  header.m_uRemotePort = n.ext_port();
  entry.addHdr(header);

  memset(&header, 0, sizeof(header));
  header.m_uRemoteIP = n.int_ip();
  entry.addHdr(header);

  // this is defensive
  if (!m_mgr.makeTunnelKey(entry, key))
    abort();

  TunnelEntry *new_ent = m_mgr.mapIn(key);

  if (new_ent != NULL)
    return new_ent->getIP();

  return m_mgr.createMapping(entry.begin(), entry.end());
}
