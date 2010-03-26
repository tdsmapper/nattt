#include <stdio.h>

#include "tun_mgr.h"
#include "tun_in_ent.h"
#include "types.h"
#include "log.h"
#include "functions.h"


TunnelInboundEntry::TunnelInboundEntry()
{
}

TunnelInboundEntry::~TunnelInboundEntry()
{
  TunnelMgr &oMgr = TunnelMgr::getInstance();

  oMgr.freeMapping(*this);
}
