#ifndef _TUN_ENT_H
#define _TUN_ENT_H

#include <list>
#include <time.h>
#include "tun_defs.h"

class TunnelEntry
{
  // Member Variables
  private:
    uint32_t m_tLocalIP;
    TunnelHdrList_t m_oHdrList;
    time_t m_tLastUsed;

  // Methods
  public:
    TunnelEntry();
    TunnelEntry(const TunnelEntry& rhs);
    TunnelEntry& operator=(const TunnelEntry& rhs);
    virtual ~TunnelEntry();

    bool addHdr(tun_hdr_t p_tHdr);

    uint32_t getIP();
    void setIP(uint32_t uIP);
    tun_hdr_t getHdr(int iIndex);
    int getNumHdrs();

    TunnelHdrIter_t begin();
    TunnelHdrIter_t end();

    time_t getLastUsed();
    void setLastUsed(time_t tLastUsed);
};

#endif
