#ifndef _TUN_QUEUE_H
#define _TUN_QUEUE_H

#include <list>

#include "tun_defs.h"

#define TUN_QUEUE_MAX 1024

class TunnelQueue
{
  // Member Variables
  private:
    std::list<tun_pkt_t> m_oList;
    int m_iMaxSize;
    int m_iSize;

  // Methods
  public:
    TunnelQueue(int p_iMaxSize = TUN_QUEUE_MAX);
    virtual ~TunnelQueue();

    bool init(int p_iMaxSize = 0);

    bool enqueue(tun_pkt_t &p_tPkt);
    bool dequeue(tun_pkt_t &p_tPkt);

    int size();
    int maxSize();
    bool hasRoom();
};

#endif
