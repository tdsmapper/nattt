#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <errno.h>
#include <fcntl.h>

#ifndef _MSC_VER
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#else
//TODO: Include windows headers
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#else
//TODO: Include windows headers
#endif

#ifdef __DARWIN_UNIX03
#include <sys/sysctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#endif

#include "tun_mgr.h"
#include "tun_defs.h"
#include "tun_in_ent.h"
#include "tun_out_ent.h"
#include "mutex_helper.h"
#include "types.h"
#include "functions.h"
#include "OS_tun_mgr.h"

#ifdef __linux
  #include <linux/if_tun.h>
#endif

using namespace std;

static TunnelMgr s_oInstance;

TunnelMgr::TunnelMgr()
  : m_bInit(false),
    m_tTimeout(0),
    m_iMaxIn(0),
    m_iMaxOut(0),
    m_iPort(0),
    m_uLocalNet(0),
    m_uMask(0),
    m_uNextIP(0), // See if there is a way to initialize m_tunFd and the m_listenFD
    m_uListenIP(0)
	#ifndef _MSC_VER /* Linux/BSD */
	,
	m_hTunFd(-1),
	m_sListenFd(-1) // The -1 for invalid file des. is handled differently by Windows.
	#endif
{

	memset(m_pTapMac, 0, 6);
}

TunnelMgr::~TunnelMgr()
{
  CLOSESOCKET(m_sListenFd);
  CLOSEDEVICE(m_hTunFd);
  
  // We need to free up our mutexes.
  int iErr = pthread_mutex_destroy(&m_tInCacheMutex);
  if (0 != iErr)
  {
    eprintf("Unable to destroy in cache mutex: %s\n", strerror(iErr));
  }

  iErr = pthread_mutex_destroy(&m_tOutCacheMutex);
  if (0 != iErr)
  {
    eprintf("Unable to destroy out cache mutex: %s\n", strerror(iErr));
  }

  iErr = pthread_mutex_destroy(&m_tMutex);
  if (0 != iErr)
  {
    eprintf("Unable to destroy createMapping mutex: %s\n", strerror(iErr));
  }
}

// This class is a singleton, so here is where we get the single instance of it.
TunnelMgr &TunnelMgr::getInstance()
{
  return s_oInstance;
}

// This is the overloaded init when u don't care about setting
// the various sizes of queues and whatnot
bool TunnelMgr::init(uint32_t p_uListenIP, uint16_t port)
{
  return init(p_uListenIP,
              port,
              NAT3_LOCAL_NET,
              NAT3_LOCAL_NETMASK,
              TUN_MGR_MAX_LRU,
              TUN_MGR_MAX_LRU,
              TUN_MGR_MAX_PKT_QUEUE,
              TUN_MGR_MAX_PKT_QUEUE);
}

bool TunnelMgr::init(uint32_t p_uListenIP,
                     int p_iPort,
                     uint32_t p_uLocalNet,
                     uint32_t p_uMask,
                     int p_iMaxIn,
                     int p_iMaxOut,
                     int p_iMaxPktIn,
                     int p_iMaxPktOut)
{
  m_bInit = false;

  try
  {
    m_uListenIP = p_uListenIP;
    m_iPort = p_iPort;

    // This is the local network that the tun device will use
    m_uLocalNet = p_uLocalNet;
    m_uMask = p_uMask;

    // When we allocate IPs to tunnels, this var decides what
    // value to set next.  We set it to 0 here so that the
    // createNewIP method can re-init it.
    m_uNextIP = 0;

    // These are the max sizes of our mappings (IP -> tunnel and tunnel -> IP)
    m_iMaxIn = p_iMaxIn;
    m_iMaxOut = p_iMaxOut;
    m_oInCache.init(m_iMaxIn);
    m_oOutCache.init(m_iMaxOut);

    // Here we are setting up the mutexes.  This allocates state and stuff...
    int iErr = pthread_mutex_init(&m_tInCacheMutex, NULL);
    if (0 != iErr)
    {
      eprintf("Unable to init in cache mutex: %s\n", strerror(iErr));
      throw iErr;
    }

    iErr = pthread_mutex_init(&m_tOutCacheMutex, NULL);
    if (0 != iErr)
    {
      eprintf("Unable to init out cache mutex: %s\n", strerror(iErr));
      throw iErr;
    }

    iErr = pthread_mutex_init(&m_tMutex, NULL);
    if (0 != iErr)
    {
      eprintf("Unable to init createMapping mutex: %s\n", strerror(iErr));
      throw iErr;
    }

    // Set the max packet queue sizes.
    m_oInboundQueue.init(p_iMaxPktIn);
    m_oOutboundQueue.init(p_iMaxPktOut);

    // These are variables for reading packets off the FDs.
    // After reading, these variables are enqueued.
    memset(&m_tInReadPkt, 0, sizeof(m_tInReadPkt));
    memset(&m_tInWritePkt, 0, sizeof(m_tInWritePkt));
    memset(&m_tOutReadPkt, 0, sizeof(m_tOutReadPkt));
    memset(&m_tOutWritePkt, 0, sizeof(m_tOutWritePkt));

    m_bInit = true;

    // Windows specific Init
#ifdef _MSC_VER
    // Free up and clear any open file descriptors.
    try
    {
      CLOSEDEVICE(m_hTunFd);
    }
    catch (...) { } // Invalid FD/Already closed

    try
    {
      CLOSESOCKET(m_sListenFd);
    }
    catch (...) { } // Invalid FD/Already closed

    // Linux/BSD Init
#else 
    // Free up and clear any open file descriptors.
    if (m_hTunFd > -1)
    {
      CLOSEDEVICE(m_hTunFd);
      m_hTunFd = -1;
    }
    if (m_sListenFd > -1)
    {
      CLOSESOCKET(m_sListenFd);
      m_sListenFd = -1;
    }
#endif /* _MSC_VER */

  }
  catch (...)
  {
    m_bInit = false;
    eprintf("Caught Exception\n");
  }

  return m_bInit;
}

// This is the main loop...
/* Rewritten per OS */
//bool TunnelMgr::listen()
//{
//  OS_listen();
//  return true;
//}

bool TunnelMgr::timeout()
{
// Notice that timeouts are never used for now.
  return false;
}

// We have a tunnel to create, make a local IP.
uint32_t TunnelMgr::createMapping(TunnelHdrIter_t p_oBegin,
                                  TunnelHdrIter_t p_oEnd)
{
  uint32_t uRet = 0;

  char szTempKey[36];
  uint32_t uOuterIP = 0;
  uint16_t uOuterPort = 0;
  uint32_t uInnerIP = 0;

  // Are there any headers?
  if (p_oBegin == p_oEnd)
  {
    eprintf("begin is equal to end.\n");
  }
  else
  {
    // FOr a tunnel we need to know the other side's <ExternalIP> : <External port> : <Internal IP>
    TunnelHdrIter_t tIter = p_oBegin;
    uOuterIP = (*tIter).m_uRemoteIP;
    uOuterPort = (*tIter).m_uRemotePort;

    tIter++;

    if (tIter == p_oEnd)
    {
      eprintf("only 1 entry in list (need 2).\n");
    }
    else
    {
      uInnerIP = (*tIter).m_uRemoteIP;
	{
		char szIP[16];
		net_itoa(uInnerIP, szIP);
		dprintf("createMapping with IP:%s\n", szIP);  
	}
      // Now get a string that represents this tunnel so we can put it in our
      // LRU cache.
      memset(szTempKey, 0, 36);
      if (!makeTunnelKey(uOuterIP, uOuterPort, uInnerIP, szTempKey, 36))
      {
        eprintf("Unable to create tunnel key.\n");
      }
      else
      {
        string sKey(szTempKey);
        //
        // CRITICAL SECTION BEGIN
        //
        {
          MutexHelper oMutex(m_tMutex);

          // The resolver and the tunnel manager use this, so we need a critical section.
          uRet = createNewIP();
        }
        //
        // CRITICAL SECTION END
        //

        // This code is outside the critical section
        // because the mapIn & mapOut methods may need
        // to access each others' mutexes if an insert
        // causes a removal (from freeMapping()).  Look 
        // here first if there are synchronization problems.
        if (0 != uRet)
        {
          // Create mappings for this new IP.
          TunnelEntry *pInEnt = new TunnelInboundEntry();
          TunnelEntry *pOutEnt = new TunnelOutboundEntry();
          for (TunnelHdrIter_t tIter2 = p_oBegin;
               p_oEnd != tIter2;
               tIter2++)
          {
            pInEnt->addHdr(*tIter2);
            pOutEnt->addHdr(*tIter2);
          }

          pInEnt->setIP(uRet);
          pOutEnt->setIP(uRet);

          // Set the mappings in our lookup caches.
          mapIn(sKey, pInEnt);
          mapOut(uRet, pOutEnt);
        }
      }
    }
  }

  return uRet;
}

bool TunnelMgr::freeMapping(TunnelInboundEntry &p_oEnt)
{
  bool bRet = false;

  // This was an inbound entry that was removed so we need to be sure it 
  // is also removed from the OUTBOUND cache
	dprintf("freeMapping inbound on IP:%u\n", p_oEnt.getIP()); 
  //
  // CRITICAL SECTION BEGIN
  //
  {
    MutexHelper oMH(m_tOutCacheMutex);

    uint32_t uIP = p_oEnt.getIP();
    m_oOutCache.remove(uIP);
    bRet = true;
  }
  //
  // CRITICAL SECTION END
  //

  return bRet;
}

bool TunnelMgr::freeMapping(TunnelOutboundEntry &p_oEnt)
{
  bool bRet = false;

  // This was an outbound entry that was removed so we need to be sure it 
  // is also removed from the INBOUND cache
	dprintf("freeMapping outbound on IP:%u\n", p_oEnt.getIP());
  string sKey;
  if (!makeTunnelKey(p_oEnt, sKey))
  {
    eprintf("Unable to create tunnel key.\n");
  }
  else
  {
    //
    // CRITICAL SECTION BEGIN
    //
    {
      MutexHelper oMH(m_tInCacheMutex);

      m_oInCache.remove(sKey);
      bRet = true;
    }
    //
    // CRITICAL SECTION END
    //
  }

  return bRet;
}

bool TunnelMgr::replaceIp(tun_pkt_t &p_tPkt) 
{
  char szKey[36];
  memset(szKey, 0, 36);
  struct ip *pIpHdr = (struct ip *) p_tPkt.m_pData;
  uint32_t uNewSrcIP = 0; 

  if (!makeTunnelKey(p_tPkt.m_uIP, p_tPkt.m_uPort, ntohl(pIpHdr->ip_src.s_addr), szKey, 36))
  {
    eprintf("Unable to create mapping key.\n");
    return false;
  }

  string sKey(szKey);

  // If there is no current mapping for this tunnel, we need to make a new one.
  TunnelEntry *pEnt = mapIn(sKey);
  if (NULL == pEnt)
  {
    tun_hdr_t tHdr;
    TunnelEntry oEnt;

    memset(&tHdr, 0, sizeof(tHdr));
    tHdr.m_uRemoteIP = p_tPkt.m_uIP;
    tHdr.m_uRemotePort = p_tPkt.m_uPort;
    oEnt.addHdr(tHdr);

    memset(&tHdr, 0, sizeof(tHdr));
    tHdr.m_uRemoteIP = ntohl(pIpHdr->ip_src.s_addr);
    tHdr.m_uLocalIP = ntohl(pIpHdr->ip_dst.s_addr);
    oEnt.addHdr(tHdr);

    // Get a new / available IP.
    uNewSrcIP = createMapping(oEnt.begin(), oEnt.end());
  }
  // Otherwise, there is a tunnel.
  else
  {
    // Get its IP.
    uNewSrcIP = pEnt->getIP();
  }

  // If we couldn't find an IP, we're stuck.
  if (0 == uNewSrcIP)
  {
    eprintf("Unable to create key.\n");
  }
  else
  {
    // This new IP will be the "local" src IP of this tunnel.
dprintf("replaceip original src is %s\n", inet_ntoa(pIpHdr->ip_src));
dprintf("replaceip original dst is %s\n", inet_ntoa(pIpHdr->ip_dst));
    pIpHdr->ip_src.s_addr = htonl(uNewSrcIP);
    pIpHdr->ip_dst.s_addr = htonl(m_uLocalNet + 1);
dprintf("replace ip new src is %s\n", inet_ntoa(pIpHdr->ip_src));
dprintf("replace ip new dest is %s\n", inet_ntoa(pIpHdr->ip_dst));
	pIpHdr->ip_sum = 0;
    pIpHdr->ip_sum = checksum((uint16_t *) pIpHdr, (pIpHdr->ip_hl)*4);
    p_tPkt.m_uIP = ntohl(pIpHdr->ip_dst.s_addr);

    return true;
  }

  return false;
}

bool TunnelMgr::fwdOut(tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  TunnelEntry *pEnt = NULL;
  struct ip *pIpHdr = (struct ip *) p_tPkt.m_pData;

  // Make sure there's any data to even send.
  if (NULL == p_tPkt.m_pData)
  {
    eprintf("Unable to send packet with NULL data.\n");
  }
  else 
  {
    uint32_t uIP = htonl(pIpHdr->ip_dst.s_addr);
    // If there is no mapping for this internal IP, then there is an error. 
    // The resovler should have set this up... yeah the resovler, not the
    // resolver.
    if (NULL == (pEnt = mapOut(uIP)))
    {
      char szIP[16];
      memset(szIP, 0, 16);
      net_itoa(uIP, szIP);
      eprintf("No mapping found for destination: %s\n", szIP);
      p_tPkt.m_uOffset = 0;
    }
    // If the offset is 0, then we are just getting started (i.e. we
    // aren't in the middle of tx'ing this packet) so we need to
    // set everything up.
    else
    {
      // Find out what the external header info for this tunnel
      // is
      TunnelHdrIter_t tIter = pEnt->begin();
      p_tPkt.m_uIP = (*tIter).m_uRemoteIP;
      p_tPkt.m_uPort = (*tIter).m_uRemotePort;

      // Now set the INNER header's destination IP to the value
      // specified by our tunnel and re-do the checksum.
      tIter++;
	pIpHdr->ip_src.s_addr = htonl(m_uListenIP);
      pIpHdr->ip_dst.s_addr = htonl((*tIter).m_uRemoteIP);
	pIpHdr->ip_sum = 0;
	pIpHdr->ip_sum = checksum((uint16_t *) pIpHdr, (pIpHdr->ip_hl)*4);
{
	char szIP1[16];
	char szIP2[16];
	char szIP3[16];
	net_itoa(uIP, szIP1);
	net_itoa(p_tPkt.m_uIP, szIP2);
	net_itoa((*tIter).m_uRemoteIP, szIP3);
      dprintf("fwdOut() - Sending packet from local IP: %s to %s:%u -> %s\n",
              szIP1,
              szIP2,
              p_tPkt.m_uPort,
              szIP3);
}
      // Write away...
      if (!writePkt((HANDLE)m_sListenFd, p_tPkt)) // HANDLE for Windows. Will work on Linux
      {
        eprintf("Unable to writePkt.  Dropping.\n");
        // This will cause us to destroy the packet below.
      }
      else
      {
        bRet = true;
      }
      p_tPkt.m_uOffset = 0;
    }
  }

  // This means the packet is done being sent, and the data needs
  // to be cleaned up.
  if (0 == p_tPkt.m_uOffset && NULL != p_tPkt.m_pData)
  {
    dprintf("destroying packet.\n");
    destroyPkt(p_tPkt);
  }

  return bRet;
}

// Synchronized cache lookups / inserts.
TunnelEntry *TunnelMgr::mapIn(string p_sKey, TunnelEntry *p_pEnt /*= NULL*/)
{
  TunnelEntry *pRet = NULL;
	dprintf("mapin with key:%s\n", p_sKey.c_str());
  //
  // CRITICAL SECTION BEGIN
  //
  {
    MutexHelper oMH(m_tInCacheMutex);

    if (NULL != p_pEnt)
    {
      if (m_oInCache.get(p_sKey) == NULL)
          m_oInCache.add(p_sKey, *p_pEnt);
      pRet = p_pEnt;
    }
    else
    {
      pRet = m_oInCache.get(p_sKey);
    }
  }
  //
  // CRITICAL SECTION END
  //

  return pRet;
}

// Synchronized cache lookups / inserts.
TunnelEntry *TunnelMgr::mapOut(uint32_t p_uSrcIP, TunnelEntry *p_pEnt)
{
  TunnelEntry *pRet = NULL;
	{
	char szIP[16];
	net_itoa(p_uSrcIP, szIP);
	dprintf("mapout with IP:%s\n", szIP);
	}
  //
  // CRITICAL SECTION BEGIN
  //
  {
    MutexHelper oMH(m_tOutCacheMutex);
    if (NULL != p_pEnt)
    {
      m_oOutCache.add(p_uSrcIP, *p_pEnt);
      pRet = p_pEnt;
    }
    else
    {
      pRet = m_oOutCache.get(p_uSrcIP);
    }
  }
  //
  // CRITICAL SECTION END
  //

  return pRet;
}

// This does re-entrant paxket writing
bool TunnelMgr::writePkt(HANDLE p_iFd, tun_pkt_t &p_tPkt, bool p_bTun /*= false*/)
{
  bool bRet = true;
  int iTemp = 0;

  p_tPkt.m_bComplete = false;

  // If this is the tun interface it don't speak "paxket".
  if (p_bTun)
  {
    // Write wherever we left off.
#ifdef _MSC_VER
  OVERLAPPED stOverlap = {0};
  DWORD dwBytesWritten = 0;
  if (!WriteFile(p_iFd, &(p_tPkt.m_pData[0]), p_tPkt.m_uOffset, &dwBytesWritten , &stOverlap))
  {
    dprintf("WriteFile failed with %d\n", GetLastError());
  }
  iTemp = dwBytesWritten;
#else
  iTemp = write(p_iFd, &(p_tPkt.m_pData[0]), p_tPkt.m_uOffset);
          dprintf("writepkt to tun %d bytes\n", iTemp);
#endif

  }
  else
  {
    // Tell this socket where we are sending.
    struct sockaddr_in tAddr;
    memset(&tAddr, 0, sizeof(tAddr));
    tAddr.sin_family = AF_INET;
    tAddr.sin_port = htons(p_tPkt.m_uPort);
    tAddr.sin_addr.s_addr = htonl(p_tPkt.m_uIP);
    // Send a tun packet to the other end
    iTemp = sendto((SOCKET)p_iFd, p_tPkt.m_pData, p_tPkt.m_uSize, 0, (struct sockaddr *) &tAddr, sizeof(tAddr));
    dprintf("Write request to socket %x IP, %d bytes, %s data\n", p_tPkt.m_uIP, p_tPkt.m_uSize, p_tPkt.m_pData);
    dprintf("writepkt to %d socket %d bytes %x ip, %d port\n", p_iFd, iTemp, tAddr.sin_addr.s_addr, tAddr.sin_port);
  }

  if (iTemp <= 0
      && EINTR != errno
      && EAGAIN != errno)
  {
    eprintf("Unable to send to socket %d: %s, errno:%d\n", p_iFd, strerror(errno), errno);
    bRet = false;
  }
  // Update the offset so we don't send this data more than once.
  else if (iTemp > 0)
  {
    p_tPkt.m_uOffset += iTemp;
  }

  // If we sent it all, then set the state to reflect that it's
  // done.
  if (p_tPkt.m_uOffset == p_tPkt.m_uSize)
  {
    p_tPkt.m_bComplete = true;
    p_tPkt.m_uOffset = 0;
    bRet = true;
  }

  return bRet;
}

bool TunnelMgr::convertToFrame(tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  dprintf("convertoframe being called\n");
  if (NULL == p_tPkt.m_pData)
  {
    eprintf("Packet has NULLL data.\n");
  }
  else if (!p_tPkt.m_bComplete)
  {
    eprintf("Packet not complete yet.\n");
  }
  // <TODO> need to do frag logic.
  else if ((int) p_tPkt.m_uSize > m_iTunMTU)
  {
    eprintf("Fragmentation not supported... IP packet is: %u bytes, which is greater than MTU (%d)\n",
            (unsigned) p_tPkt.m_uSize,
            m_iTunMTU);
  }

  else
  {
    int iLen = m_iTunMTU + 14;
    char *pEthFrame = new char[iLen];
    memset(pEthFrame, 0, m_iTunMTU);
    struct ether_header *pEthHdr = (struct ether_header *) pEthFrame;

    memcpy(pEthHdr->ether_shost, m_pTapMac, 6);
    memcpy(pEthHdr->ether_dhost, m_pTapMac, 6);
    pEthHdr->ether_type = htons(ETHERTYPE_IP);
    memcpy(&(pEthFrame[sizeof(ether_header)]), p_tPkt.m_pData, p_tPkt.m_uSize);
    delete[] p_tPkt.m_pData;
    p_tPkt.m_pData = pEthFrame;
    p_tPkt.m_uOffset = p_tPkt.m_uSize + 14;
    p_tPkt.m_uSize = iLen;

    bRet = true;
  }

  return bRet;
}

// Allocate IPs
uint32_t TunnelMgr::createNewIP()
{
  uint32_t uRet = 0;
  if ((m_uNextIP & m_uMask) != m_uLocalNet)
  {
    // Skip the first IP after the network because that should be us.
    m_uNextIP = m_uLocalNet + 2;
  }

  uRet = m_uNextIP++;
  uint32_t uStart = uRet;
  // Check if this is already allocated
  while (NULL != mapOut(uRet))
  {
    uRet = m_uNextIP++;

    if ((m_uNextIP & m_uMask) != m_uLocalNet)
    {
      // Skip the first IP after the network because that should be us.
      m_uNextIP = m_uLocalNet + 2;
    }

    // We couldn't find a free one.
    if (uRet == uStart)
    {
      eprintf("Unable to allocate IP address because all are in use.\n");
      uRet = 0;
      break;
    }
  }

  return uRet;
}

// Hardly warrants a method.
#ifndef _MSC_VER
bool TunnelMgr::setNonblocking(int p_iFd)
{
  bool bRet = false;
  int iFlags = 0;

  // check for O_NONBLOCK
#if defined(O_NONBLOCK)
  if (-1 == (iFlags = fcntl(p_iFd, F_GETFL, 0)))
  {
    iFlags = 0;
  }

  bRet = (0 ==  fcntl(p_iFd, F_SETFL, iFlags | O_NONBLOCK));
#else
  iFlags = 1;
  bRet = (0 == ioctl(p_iFd, FIOBIO, &iFlags));
#endif

  return bRet;
}
#endif



#ifndef _MSC_VER
bool TunnelMgr::readFrame(HANDLE p_iFd, tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  // *GROAN* Let's assume we get the whole frame in 1 read... :-/
  if (NULL == p_tPkt.m_pData)
  {
    p_tPkt.m_uSize = ETHERNET_READ_SIZE;
    p_tPkt.m_uOffset = 0;
    p_tPkt.m_bComplete = false;
    p_tPkt.m_pData = new char[p_tPkt.m_uSize];
    memset(p_tPkt.m_pData, 0, p_tPkt.m_uSize);
  }

  int iErr = read(p_iFd, &(p_tPkt.m_pData[p_tPkt.m_uOffset]), p_tPkt.m_uSize - p_tPkt.m_uOffset);
  if (iErr <= 0
      && EAGAIN != errno
      && EINTR != errno)
  {
    eprintf("Unable to read Ethernet frame: %s\n", strerror(errno));
    destroyPkt(p_tPkt);
  }
  else
  {
    p_tPkt.m_uOffset += iErr;

    // <EMO> Here's where we "ASSUME" we get the whole frame..
    p_tPkt.m_uSize = iErr;
    p_tPkt.m_bComplete = true;
    // </EMO>

    bRet = true;
  }
  if (p_tPkt.m_uOffset == p_tPkt.m_uSize)
  {
    p_tPkt.m_bComplete = true;
    dprintf("Setting frame to complete...\n");
  }
  else
  {
	  dprintf("Frame incomplete.\n");
  }
  return bRet;
}
#endif /* _MSC_VER */

bool TunnelMgr::handleFrame(tun_pkt_t &p_tPkt)
{
  bool bRet = false;

  if (!p_tPkt.m_bComplete)
  {
    eprintf("Unable to handle frame when structure is not complete.\n");
  }
  else
  {
    struct ether_header *pEth = (struct ether_header *) p_tPkt.m_pData;
    if (ETHERTYPE_ARP == ntohs(pEth->ether_type))
    {
      struct arphdr *pArp = (struct arphdr *) &(p_tPkt.m_pData[sizeof(struct ether_header)]);

      if (ARPHRD_ETHER == ntohs(pArp->ar_hrd)
        && ETHERTYPE_IP == ntohs(pArp->ar_pro)
        && 6 == pArp->ar_hln
        && 4 == pArp->ar_pln
        && ARPOP_REQUEST == ntohs(pArp->ar_op))
      {
        dprintf("handling ARP request.\n");
        char *pBuff = (char *) pArp;
        uint32_t uSrcIP = 0;
        uint32_t uResponseIP = 0;
        u_char pSrcMac[6];
        u_char pResponseMac[6];

        memcpy(pSrcMac, &(pBuff[TUN_MGR_ARP_SHA]), 6);
        memcpy(pResponseMac, &(pBuff[TUN_MGR_ARP_THA]), 6);
        memcpy(&uSrcIP, &(pBuff[TUN_MGR_ARP_SPA]), 4);
        memcpy(&uResponseIP, &(pBuff[TUN_MGR_ARP_TPA]), 4);
        if ((ntohl(uResponseIP) & m_uMask) != m_uLocalNet)
        {
          dprintf("Got arp request for unknown IP: %x\n", ntohl(uResponseIP));
          destroyPkt(p_tPkt);
        }
        else
        {
          memcpy(&(pBuff[TUN_MGR_ARP_THA]), pSrcMac, 6);
          memcpy(&(pBuff[TUN_MGR_ARP_SHA]), m_pTapMac, 6);
          memcpy(&(pBuff[TUN_MGR_ARP_TPA]), &uSrcIP, 4);
          memcpy(&(pBuff[TUN_MGR_ARP_SPA]), &uResponseIP, 4);
          pArp->ar_op = htons(ARPOP_REPLY);

          bRet = true;
        }
      }
    }
    else if (ETHERTYPE_IP == ntohs(pEth->ether_type))
    {
      struct ip *pIP = (struct ip *) &(p_tPkt.m_pData[sizeof(struct ether_header)]);
      uint16_t uLen = ntohs(pIP->ip_len);
      char *pTmp = new char[uLen];
      memcpy(pTmp, pIP, uLen);
      p_tPkt.m_uSize = uLen;
      delete[] p_tPkt.m_pData;
      p_tPkt.m_pData = pTmp;

      bRet = true;
    }
    else
    {
      eprintf("Unknown ethertype: %x\n", ntohs(pEth->ether_type));
      bRet = false;
      destroyPkt(p_tPkt);
    }
  }

  return bRet;
}

uint32_t TunnelMgr::getMask()
{
  return m_uMask;
}

uint32_t TunnelMgr::getLocalNet()
{
  return m_uLocalNet;
}

// Simple helper.
bool TunnelMgr::net_itoa(uint32_t p_uIP, char *p_szOutput)
{
  bool bRet = false;

  if (NULL == p_szOutput)
  {
    eprintf("NULL output buffer.\n");
  }
  else
  {
    int iA = (p_uIP >> 24) & 0xFF;
    int iB = (p_uIP >> 16) & 0xFF;
    int iC = (p_uIP >> 8) & 0xFF;
    int iD = p_uIP & 0xFF;

    sprintf(p_szOutput, "%d.%d.%d.%d", iA, iB, iC, iD);
    bRet = true;
  }

  return bRet;
}

bool TunnelMgr::makeTunnelKey(TunnelEntry &p_oEnt, std::string &p_sOutputKey)
{
  bool bRet = false;

  // For now we assume 1 level of NAT
  TunnelHdrIter_t tIter = p_oEnt.begin();
  uint32_t uOuterIP = (*tIter).m_uRemoteIP;
  uint16_t uOuterPort = (*tIter).m_uRemotePort;

  tIter++;

  if (tIter == p_oEnt.end())
  {
    eprintf("only 1 entry in list (need 2).\n");
  }
  else
  {
    uint32_t uInnerIP = (*tIter).m_uRemoteIP;

    char szKey[36];
    memset(szKey, 0, 36);

    bRet = makeTunnelKey(uOuterIP, uOuterPort, uInnerIP, szKey, 36);
    if (bRet)
    {
      p_sOutputKey = szKey;
    }
  }

  return bRet;
}

bool TunnelMgr::makeTunnelKey(uint32_t p_uOuterIP,
                              uint16_t p_uOuterPort,
                              uint32_t p_uInnerIP,
                              char *p_pOutBuffer,
                              size_t p_uSize)
{
  bool bRet = false;

  char szOuterIP[16];
  char szInnerIP[16];

  memset(szOuterIP, 0, 16);
  memset(szInnerIP, 0, 16);
  memset(p_pOutBuffer, 0, p_uSize);

  if (NULL == p_pOutBuffer)
  {
    eprintf("NULL out buffer specified.\n");
  }
  else if (36 > p_uSize)
  {
    eprintf("Input buffer is too small %u < 36\n", (unsigned) p_uSize);
  }
  else if (!net_itoa(p_uOuterIP, szOuterIP))
  {
    eprintf("Unable to convert outer source IP.\n");
  }
  else if (!net_itoa(p_uInnerIP, szInnerIP))
  {
    eprintf("Unable to convert source port of INNER header.\n");
  }
  else
  {
    // This will be <outerIP>:<outerPort>:<innerIP>
    sprintf(p_pOutBuffer, "%s:%u:%s", szOuterIP, (p_uOuterPort), szInnerIP);
    bRet = true;
  }

  return bRet;
}

uint16_t TunnelMgr::checksum(uint16_t *p_pBuff, int p_iSize)
{
  register long lSum = 0;
  for (lSum = 0; p_iSize > 0; p_iSize -= 2)
  {
    lSum += *p_pBuff++;
  }

  lSum = (lSum >> 16) + (lSum & 0xFFFF);
  lSum += (lSum >> 16);

  return ~lSum;
}

bool TunnelMgr::destroyPkt(tun_pkt_t &p_tPkt)
{
  if (NULL != p_tPkt.m_pData)
  {
    delete[] p_tPkt.m_pData;
  }

  memset(&p_tPkt, 0, sizeof(p_tPkt));

  return true;
}
