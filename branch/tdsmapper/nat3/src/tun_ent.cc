#include <stdio.h>

#include <list>

#include "tun_ent.h"
#include "types.h"
#include "functions.h"
#include "log.h"

using namespace std;

TunnelEntry::TunnelEntry()
 : m_tLocalIP(0),
   m_tLastUsed(0)
{
  
}

TunnelEntry::TunnelEntry(const TunnelEntry& rhs) 
{
  m_tLocalIP = rhs.m_tLocalIP;
  m_oHdrList = rhs.m_oHdrList;
  m_tLastUsed = rhs.m_tLastUsed;
}

TunnelEntry& TunnelEntry::operator=(const TunnelEntry& rhs) 
{
  if (this == &rhs)
    return *this;

  m_tLocalIP = rhs.m_tLocalIP;
  m_oHdrList = rhs.m_oHdrList;
  m_tLastUsed = rhs.m_tLastUsed;
 
  return *this;
}

TunnelEntry::~TunnelEntry()
{
  
}

// Add a new header to the list of existing headers
// The first header will hold the header information necessary to route to
// a reachable destination. Additional headers describe how to route 
// internal packets.
bool TunnelEntry::addHdr(tun_hdr_t tHdr)
{
  m_oHdrList.push_back(tHdr);
  return true;
}

uint32_t TunnelEntry::getIP()
{
  return m_tLocalIP;
}

void TunnelEntry::setIP(uint32_t uIP)
{
  if (uIP > 0)
  {
    m_tLocalIP = uIP;
  }
  else
  {
    eprintf( "%s [%d] - Invalid IP Address (%d).\n",
            __FILE__,
            __LINE__,
            uIP);
  }
}

// Return the header at a given indes.
// Returns an default header if index is invalid.
tun_hdr_t TunnelEntry::getHdr(int iIndex)
{
  tun_hdr_t tRet;
  if (iIndex >= 0 ) { 
    TunnelHdrIter_t iter = begin();
    int iCount = 0;
    // look up header at position iIndex 
    while(iCount < iIndex && iter != end())
    {
      iCount++;
      ++iter;
    }  
    tRet = (iCount == iIndex) ? *iter : tRet;
    
  }
  else
  {
    eprintf( "%s [%d] - Invalid index (%d)\n",
            __FILE__,
            __LINE__,
            iIndex);  
  }
  return tRet;
}

int TunnelEntry::getNumHdrs()
{
  return m_oHdrList.size();
}

TunnelHdrIter_t TunnelEntry::begin()
{
  return m_oHdrList.begin();
}

TunnelHdrIter_t TunnelEntry::end()
{
  return m_oHdrList.end();
}

time_t TunnelEntry::getLastUsed()
{
  return m_tLastUsed;
}

void TunnelEntry::setLastUsed(time_t tLastUsed)
{
  m_tLastUsed = tLastUsed;
}
