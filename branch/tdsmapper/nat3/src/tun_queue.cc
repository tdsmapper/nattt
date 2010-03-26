#include <stdio.h>

#include <list>

#include "tun_queue.h"
#include "types.h"
#include "functions.h"
#include "log.h"

using namespace std;

TunnelQueue::TunnelQueue(int p_iMaxSize /*= TUN_QUEUE_MAX)*/)
  : m_iMaxSize(p_iMaxSize),
    m_iSize(0)
{

}

TunnelQueue::~TunnelQueue()
{
  for (list<tun_pkt_t>::iterator oIter = m_oList.begin();
       m_oList.end() != oIter;
       oIter++)
  {
    delete[] (*oIter).m_pData;
  }

  m_oList.clear();
}

bool TunnelQueue::init(int p_iMaxSize /*= 0*/)
{
  bool bRet = false;

  if (p_iMaxSize < 0)
  {
    eprintf( "%s [%d] - Max size for queue must be >= 0, but is specified as: %d\n",
            __FILE__,
            __LINE__,
            p_iMaxSize);
  }
  else
  {
    if (0 != p_iMaxSize)
    {
      m_iMaxSize = p_iMaxSize;
    }

    m_oList.clear();
    m_iSize = 0;
    bRet = true;
  }

  return bRet;
}

bool TunnelQueue::enqueue(tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  if (m_iSize < m_iMaxSize)
  {
    m_oList.push_back(p_tPkt);
    m_iSize++;
    bRet = true;
  }

  return bRet;
}

bool TunnelQueue::dequeue(tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  if (m_iSize > 0)
  {
    p_tPkt = (*m_oList.begin());
    m_oList.pop_front();
    m_iSize--;
    if (m_iSize < 0)
    {
      eprintf( "%s [%d] - Internal consistency error.  Queue is size: %d\n",
              __FILE__,
              __LINE__,
              m_iSize);
    }
    else
    {
      bRet = true;
    }
  }

  return bRet;
}

int TunnelQueue::size()
{
  return m_iSize;
}

int TunnelQueue::maxSize()
{
  return m_iMaxSize;
}

bool TunnelQueue::hasRoom()
{
  return m_iSize < m_iMaxSize;
}

