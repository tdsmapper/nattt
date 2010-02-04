#include <stdio.h>

#include "tun_mgr.h"
#include "tun_out_ent.h"
#include "types.h"
#include "functions.h"

TunnelOutboundEntry::TunnelOutboundEntry()
{

}

TunnelOutboundEntry::~TunnelOutboundEntry()
{
  TunnelMgr &oMgr = TunnelMgr::getInstance();

  oMgr.freeMapping(*this);
}
