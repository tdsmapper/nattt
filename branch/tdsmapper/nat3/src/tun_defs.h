#ifndef _TUN_DEFS_H
#define _TUN_DEFS_H

#include <list>

#include "types.h"
#include "functions.h"

#ifndef _MSC_VER
#include "stdint.h"
#endif

// Location of the tun/tap device on the system
#ifdef __linux
#define TUN_DEVICE_PATH "/dev/net/tun"
#elif defined(__DARWIN_UNIX03)
#define TUN_DEVICE_PATH "/dev/tun"
#endif

// Max number of tries to open a tun device
#define MAX_TUN_OPEN_TRY 256

// Deafult NAT3 port used for listening
#define NAT3_DEFAULT_PORT 100

// 127.254.0.0
//#define NAT3_LOCAL_NET 0x7FFE0000
#define NAT3_LOCAL_NET 0x0AFE0000

// 255.255.0.0
#define NAT3_LOCAL_NETMASK 0xFFFF0000

// Max size of LRU cache
#define TUN_MGR_MAX_LRU 1024

// Max size of packet queue
#define TUN_MGR_MAX_PKT_QUEUE 1024

#define TUN_MGR_ARP_SHA 8
#define TUN_MGR_ARP_SPA 14
#define TUN_MGR_ARP_THA 18
#define TUN_MGR_ARP_TPA 24

typedef struct
{
  uint32_t m_uIP;
  uint16_t m_uPort;
  size_t m_uSize;
  size_t m_uOffset;
  bool m_bComplete;
  char *m_pData;
} tun_pkt_t;

typedef struct
{
  uint32_t m_uRemoteIP;
  uint16_t m_uRemotePort;
  uint32_t m_uLocalIP;
  uint16_t m_uLocalPort;
} tun_hdr_t;

/* 12/16/09 - Commented out by Arun Madhavan to ease compatibility with Windows.
   Should the structure be needed, there is information online on how to do packing in Windows.

typedef struct
{
  uint32_t m_uSrcIP;
  uint32_t m_uDstIP;
  uint8_t m_uZero;
  uint8_t m_uProto;
  uint16_t m_uLen;
} __attribute__((__packed__)) tun_pseudo_hdr_t;  */

// Holds a list of headers required to route packets to the
// other end of the tunnel.
typedef std::list<tun_hdr_t> TunnelHdrList_t;
typedef TunnelHdrList_t::iterator TunnelHdrIter_t;

#endif
