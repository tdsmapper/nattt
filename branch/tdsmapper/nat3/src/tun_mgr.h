#ifndef _TUN_MGR_H
#define _TUN_MGR_H

#include "types.h"
#ifdef _MSC_VER
#include <Winsock2.h>
#include "p_thread.h"
#else
#include <pthread.h>
#endif

#include <map>
#include <string>
#include <list>

#include "lru_cache.h"
#include "tun_queue.h"
#include "tun_defs.h"
#include "functions.h"




class TunnelEntry;
class TunnelInboundEntry;
class TunnelOutboundEntry;

typedef LruCache<uint32_t, TunnelEntry > OutCache_t;
typedef LruCache<std::string, TunnelEntry > InCache_t;

class TunnelMgr
{
  //Member Variables
  private:
    bool m_bInit;
    time_t m_tTimeout;
    int m_iMaxIn;
    int m_iMaxOut;
    SOCKET m_sListenFd;
    HANDLE m_hTunFd;
    int m_iPort;
    int m_iTunMTU;
    InCache_t m_oInCache;
    OutCache_t m_oOutCache;
    std::string m_sInterface;
    TunnelQueue m_oOutboundQueue;
    TunnelQueue m_oInboundQueue;
    tun_pkt_t m_tInReadPkt;
    tun_pkt_t m_tInWritePkt;
    tun_pkt_t m_tOutReadPkt;
    tun_pkt_t m_tOutWritePkt;
    pthread_mutex_t m_tMutex;
    pthread_mutex_t m_tInCacheMutex;
    pthread_mutex_t m_tOutCacheMutex;
    uint32_t m_uLocalNet;
    uint32_t m_uMask;
    uint32_t m_uNextIP;
    uint32_t m_uListenIP;
    u_char m_pTapMac[6];

/* For Windows tunnel manager only */
#ifdef _MSC_VER

    int srcAddrSize;
    DWORD dwFlags;

    // The MAC address to use when replying for ARP from an IP address in the TUN/TAP device's network
    u_char m_uNatNetMac[6];
#endif

  // Methods
  private:
    TunnelMgr(const TunnelMgr& rhs);
    TunnelMgr& operator=(const TunnelMgr& rhs);

  public:
    TunnelMgr();
    virtual ~TunnelMgr();

    static TunnelMgr &getInstance();

    bool init(uint32_t p_uListenIP, uint16_t port);
    bool init(uint32_t p_uListenIP,
              int p_iPort,
              uint32_t p_uLocalNet,
              uint32_t p_uMask,
              int p_iMaxIn,
              int p_iMaxOut,
              int p_iMaxPktIn,
              int p_iMaxPktOut);
    bool listen();
    bool timeout();

    uint32_t createMapping(TunnelHdrIter_t p_oBegin,
                           TunnelHdrIter_t p_oEnd);
    bool freeMapping(TunnelInboundEntry &p_oEnt);
    bool freeMapping(TunnelOutboundEntry &p_oEnt);

    uint32_t getMask();
    uint32_t getLocalNet();
    static uint16_t checksum(uint16_t *p_pBuff, int p_iSize);


    bool replaceIp(tun_pkt_t &);

#ifdef _MSC_VER
    VOID WINAPI tapReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap);
    VOID WINAPI tunReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap);
    VOID WINAPI listenReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap);
#endif

  protected:
    bool fwdIn(tun_pkt_t &p_tPkt);
    bool fwdOut(tun_pkt_t &p_tPkt);
    TunnelEntry *mapIn(std::string p_sKey, TunnelEntry *p_pEnt = NULL);
    TunnelEntry *mapOut(uint32_t p_tSrcIP, TunnelEntry *p_pEnt = NULL);
    uint32_t createNewIP();
    bool convertToFrame(tun_pkt_t &p_tPkt);
    bool writePkt(HANDLE p_iFd, tun_pkt_t &p_tPkt, bool p_bTun = false);
    bool handleFrame(tun_pkt_t &p_tPkt); // Handle frames from the TAP device
    
    HANDLE openTunInterface();
    bool tcpChecksum(char *p_pBuff);

#ifndef _MSC_VER
    /* readPkt and readFrame reimplemented for Windows */
    bool readSocketPkt(HANDLE p_iFd, tun_pkt_t &p_tPkt);
    bool readTunPkt(HANDLE p_iFd, tun_pkt_t &p_tPkt);
    bool readFrame(HANDLE p_iFd, tun_pkt_t &p_tPkt);
    bool setNonblocking(int p_iFd);
#endif
    
    
#ifndef NAT3_JK
    bool configTunInterface(char *p_szDevice);
#endif
    static bool makeTunnelKey(TunnelEntry &p_oEnt, std::string &p_sKey);
    static bool makeTunnelKey(uint32_t p_uOuterSrc,
                              uint16_t p_uOuterPort,
                              uint32_t p_uInnerIP,
                              char *p_pOutBuffer,
                              size_t p_uSize);
    static bool destroyPkt(tun_pkt_t &p_tPkt);
    static void clearPkt(tun_pkt_t &p_tPkt);

    // needs to have access to mapping creation
    friend class DnsQuery;
};

#endif
