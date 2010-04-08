/* Linux/BSD specific interface implementations of tunnel manager. Interface defined by OS_tun_mgr.h*/

#ifndef _MSC_VER

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <iostream> // Compatibility with OpenWRT
#include <errno.h>
#include <fcntl.h>

#ifndef _MSC_VER
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#else
#include <Winsock2.h>
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <string.h>
#ifndef _MSC_VER
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
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

#ifdef __linux
  #include <linux/if_tun.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "tun_mgr.h"
#include "tun_defs.h"
#include "tun_in_ent.h"
#include "tun_out_ent.h"
#include "mutex_helper.h"
#include "types.h"
#include "functions.h"
#include "OS_tun_mgr.h"


#include "tun_mgr.h"
#include "OS_tun_mgr.h"
#include "types.h"
#include "functions.h"
#include "log.h"



HANDLE TunnelMgr::openTunInterface()
{

  // File descriptor for the TUN interface 
  int fd = -1;

  char *szDev = NULL;
#ifdef __DARWIN_UNIX03
  char szDeviceName[256];
  int i = -1;

#ifdef NAT3_TAP
#define NAT3_TUNTAP "tap"
#else
#define NAT3_TUNTAP "tun"
#endif

  // Try successively opening devices until we find a free one.
  do {
    sprintf(szDeviceName, "/dev/" NAT3_TUNTAP "%d", ++i);
    fd = open(szDeviceName, O_RDWR);
  } while (fd < 0 && i < MAX_TUN_OPEN_TRY);

  if (fd < 0)
    return -1;

  char qoihjp[256];
  sprintf(qoihjp, NAT3_TUNTAP "%d", i);
  szDev = qoihjp;

#undef NAT3_TUNTAP

#elif defined(__linux)
  struct ifreq ifr; 
  // open the tun device for reading
  if ((fd = open(TUN_DEVICE_PATH, O_RDWR)) < 0)
  {
    eprintf("Unable to open TUN/TAP device (%s): %s\n", TUN_DEVICE_PATH, strerror(errno));
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  // IFF_TUN   - Open a TUN device
  // IFF_NO_PI - Do not provide packet information
  // IFF_ONE_QUEUE - Only use the /tun/tap queue.  
  //                 Do not use the network device send queue.

  // create the interface
#ifdef NAT3_TAP
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE;
#else
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_ONE_QUEUE;
#endif

  if (ioctl(fd, TUNSETIFF, &ifr) < 0) 
  {
    eprintf("Unable to execute ioctl on device (%s): %s\n", TUN_DEVICE_PATH, strerror(errno)); 
    return -1;
  }

  szDev = ifr.ifr_name;
#endif // __linux + __DARWIN_UNIX03

  // Return an error if we cannot bring up the TUN interface and 
  // assign it an IP address
  if (!configTunInterface(szDev))
  {
    close(fd);
    return -1;
  }

  // return the file descriptor for the TUN interface 
  return fd; 
}

bool TunnelMgr::listen()
{
  struct sockaddr_in tInAddr;
  memset(&tInAddr, 0, sizeof(tInAddr));
  tInAddr.sin_family = AF_INET;
  tInAddr.sin_port = htons(m_iPort);
  tInAddr.sin_addr.s_addr = htonl(m_uListenIP);

  // Bomb if we were not initialized.
  if (!m_bInit)
  {
    eprintf("Unable to listen until initialized.\n");
  }
  // Open our connection for incoming packets.
  else if ((m_sListenFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
  {
    eprintf("Unable to open network listening socket: %s\n", strerror(errno));
  }
  // Make it non-blocking.
  else if (!setNonblocking(m_sListenFd))
  {
    eprintf("Unable to set inbound socket to non-blocking: %s\n", strerror(errno));
  }
  // Open our tun interface (the outbound FD).
  else if ((m_hTunFd = openTunInterface()) < 0)
  {
    eprintf("Unable to create tun device: %s\n", strerror(errno));
  }
  else if (!setNonblocking(m_hTunFd))
  {
    eprintf("Unable to set internal socket to non-blocking: %s\n", strerror(errno));
  }
  // Bind our inbound interface to our "well known" port.
  else if (0 != bind(m_sListenFd, (struct sockaddr *) &tInAddr, sizeof(tInAddr)))
  {
    eprintf("Unable to bind to port: %d: %s\n", m_iPort, strerror(errno));
  }
  else
  {
    struct timeval tSleep;
    fd_set tReadFDs;
    fd_set tWriteFDs;

    // We need this for select.
    int iMax = (m_sListenFd > m_hTunFd) ? m_sListenFd : m_hTunFd;

    // While all is well...
    while (m_bInit)
    {
      tSleep.tv_sec = 20;
      tSleep.tv_usec = 0;

      // We always want to listen, so the read list gets both FDs.
      FD_ZERO(&tReadFDs);
      FD_SET(m_sListenFd, &tReadFDs);
      FD_SET(m_hTunFd, &tReadFDs);

      // We only care about writing if there are packets in our queues.
      // So, add them selectively.
      FD_ZERO(&tWriteFDs);
      if (NULL != m_tInWritePkt.m_pData || m_oInboundQueue.size() > 0)
      {
        FD_SET(m_hTunFd, &tWriteFDs);
      }
      if (NULL != m_tOutWritePkt.m_pData || m_oOutboundQueue.size() > 0)
      {
        FD_SET(m_sListenFd, &tWriteFDs);
      }

      // Select away...
      int iReady = select(iMax + 1, &tReadFDs, &tWriteFDs, 0, &tSleep);
      if (iReady < 0 && EINTR != errno)
      {
        eprintf("Error occured while selecting: %s\n", strerror(errno));
        m_bInit = false;
      }
      // If we have work to do...
      else if (iReady > 0)
      {
        // Are we ready to send inward?
		// (Client) TunFd: From outside world to Internal applications
        if (FD_ISSET(m_hTunFd, &tWriteFDs))
        {
          // Make sure there's data to be sent (from a previous unfinished write).
          if (NULL != m_tInWritePkt.m_pData)
          {
            dprintf("Writing unfinished packet to tun FD: 0x%x : %u\n",m_tInWritePkt.m_uIP, m_tInWritePkt.m_uPort);
            if (!writePkt(m_hTunFd, m_tInWritePkt, true))
            {
              dprintf("Unable to write frame.\n");
            }
            destroyPkt(m_tInWritePkt);
          }
          // If no data, dequeue the next packet.
          else if (m_oInboundQueue.size() > 0)
          {
            dprintf("Writing new packet to tun FD\n");
            if (!m_oInboundQueue.dequeue(m_tInWritePkt))
            {
              dprintf("Unable to dequeue packet from inbound queue.\n");
            }
            else if (!writePkt(m_hTunFd, m_tInWritePkt, true))
            {
              dprintf("Unable to write frame.\n");
            }
            destroyPkt(m_tInWritePkt);
          }
        }

        // If we are ready to send outbound packets...
		// (Client, Server): From 
        if (FD_ISSET(m_sListenFd, &tWriteFDs))
        {
          // Check if there is an unfinished packet.
          if (NULL != m_tOutWritePkt.m_pData)
          {
            dprintf("Writing unfinished packet to listen FD\n");
            if (!fwdOut(m_tOutWritePkt))
            {
              dprintf("Unable to fwdOut()\n");
            }
          }
          // Otherwise, dequeue the next packet.
          else if (m_oOutboundQueue.size() > 0)
          {
            dprintf("Writing new packet to listen FD\n");
            if (!m_oOutboundQueue.dequeue(m_tOutWritePkt))
            {
              dprintf("Unable to dequeue packet from outbound queue.\n");
            }
            else if (!fwdOut(m_tOutWritePkt))
            {
              dprintf("Unable to fwdOut()\n");
            }
          }
        }

        // If we have room for another inbound packet, AND there's something standing by...
        if (m_oInboundQueue.hasRoom() && FD_ISSET(m_sListenFd, &tReadFDs))
        {
          dprintf("Reading new packet from listen FD\n");
          if (!readSocketPkt(m_sListenFd, m_tInReadPkt))
          {
            dprintf("Unable to read packet from inbound FD %d: %s\n", m_sListenFd, strerror(errno));
          }

          // If we have the whole packet...
          if (m_tInReadPkt.m_bComplete)
          {
            if (!replaceIp(m_tInReadPkt))
            {
              dprintf("Couldn't set up IP addresses in header\n");
            }
#ifdef NAT3_TAP
            else if (!convertToFrame(m_tInReadPkt))
            {
              dprintf("Unable to convert IP packet to Ethernet frame.\n");
              // destroyPkt(m_tInWritePkt);
            }
#endif /* NAT3_TAP */

            // Enqueue it.
            else if (!m_oInboundQueue.enqueue(m_tInReadPkt))
            {
              dprintf("Unable to enqueue inbound packet.\n");
              delete[] m_tInReadPkt.m_pData;
            }
            else
            {
              m_tInReadPkt.m_bComplete = false;
            }

            // When we're done, clear the structure out, but don't free it's mem (that
            // is in the queue now).
            memset(&m_tInReadPkt, 0 , sizeof(m_tInReadPkt));
          }
          else
          {
            dprintf("but it didn't complete\n");
          }
        }

        // If there is room in the outbound queue and we have something pending on the tun FD...
        if (m_oOutboundQueue.hasRoom() && FD_ISSET(m_hTunFd, &tReadFDs))
        {
          dprintf("Reading new packet from tun FD\n");

          // Get the next packet.
          // TAP Device: Read the frame, and Handle it - ARP/IP etc
#ifdef NAT3_TAP
          if (!readFrame(m_hTunFd, m_tOutReadPkt))
          {
            dprintf("Unable to read packet from TAP FD %d: %s\n", m_hTunFd, strerror(errno));
          }
          // If we have the whole packet...
          if (m_tOutReadPkt.m_bComplete)
          {
            if (!handleFrame(m_tOutReadPkt)) // handleFrame changed to not enqueue
            {
              dprintf("Unable to handle new frame.\n");
              destroyPkt(m_tOutReadPkt);
            }
          }
#else
          // TUN Device: Read the packet, and just enqueue it
          if (!readTunPkt(m_hTunFd, m_tOutReadPkt))
          {
            dprintf("Unable to read packet from tun FD %d: %s\n", m_hTunFd, strerror(errno));
          }
          if(m_tOutReadPkt.m_bComplete)
          {
            // Just enqueue. It already is an IP packet
            if(!m_oOutboundQueue.enqueue(m_tOutReadPkt))
            {
              dprintf("Unable to enqueue TUN packet!\n");
              delete[] m_tOutReadPkt.m_pData;
            }
          }
#endif
          // When we're done, clear the structure out, but don't free its mem (that
          // is in the queue now).
          memset(&m_tOutReadPkt, 0, sizeof(m_tOutReadPkt));
        }
      }
    }
  }
  return true;
}

bool TunnelMgr::configTunInterface(char *p_szDeviceName) 
{
  bool bRet = false; 

  char szIfconfigCall[256];
  char dfgdf[32], jjjjjjj[32], szLocalNet[32];

  net_itoa(m_uLocalNet, szLocalNet);
// <EMO>
  net_itoa(m_uLocalNet + 1, dfgdf);
// </EMO>
  net_itoa(m_uMask, jjjjjjj);

#ifdef NAT3_TAP
  // tap device, and we don't want arp because arp sux
  sprintf(szIfconfigCall,
          "ifconfig %s %s netmask %s",
          p_szDeviceName,
          dfgdf,
          jjjjjjj);
#else
  // Bring up the TUN device
  // ex: ifconfig tun0 127.254.0.1 127.254.0.1 netmask 255.255.0.0 up 
  sprintf(szIfconfigCall,
          "ifconfig %s %s %s netmask %s",
          p_szDeviceName,
          dfgdf,
          dfgdf,
          jjjjjjj);
#endif

  // Execute the szIfconfigCall at most 2 times.
  // There's a bug in Ubuntu that returns
  //   'SIOCSIFNETMASK: Cannot assign requested address' 
  //   even though the IP is actually set.  Trying this a second time
  //   should succeed. 
  int iStatus = system(szIfconfigCall); if (0 == iStatus) {
    bRet = true;
  }
  else   
  {
    iStatus = system(szIfconfigCall);
    if (0 == iStatus)
    {
      bRet = true;
    }
    else 
    {
      dprintf("Unable to bring up interface (%s): %s\n", p_szDeviceName, strerror(errno));    
      bRet = false;
    }
  }

#if defined(__DARWIN_UNIX03) && !defined(NAT3_TAP)
  if (bRet)
  {
    memset(szIfconfigCall, 0, 256);
    sprintf(szIfconfigCall, "route add -inet %s -netmask %s -iface %s", szLocalNet, jjjjjjj, p_szDeviceName);
    iStatus = system(szIfconfigCall);
    if (0 != iStatus)
    {
      dprintf("Unable to set local route...\n");
      bRet = false;
    }
  }
#endif //__DARWIN_UNIX03

  // get the MTU
  if (bRet) {
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      eprintf("Couldn't open socket: %s\n", strerror(errno));
      return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, p_szDeviceName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
      eprintf("Couldn't read MTU of device %s: %s\n", p_szDeviceName,
          strerror(errno));
      bRet = false;
    }
    else
    {
      m_iTunMTU = ifr.ifr_mtu;
    }

#ifdef __linux
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, p_szDeviceName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
      eprintf("Unable to get MAC addr of device %s: %s\n", p_szDeviceName, strerror(errno));
      bRet = false;
    }
    else
    {
      memcpy(m_pTapMac, &ifr.ifr_addr.sa_data, 6);
      dprintf("GOT MAC: %x:%x:%x:%x:%x:%x\n", m_pTapMac[0], m_pTapMac[1], m_pTapMac[2], m_pTapMac[3], m_pTapMac[4], m_pTapMac[5]);
    }
#elif defined(__DARWIN_UNIX03)
    size_t tSize = 0;
    int pBlah[6];
    pBlah[0] = CTL_NET;
    pBlah[1] = PF_ROUTE;
    pBlah[2] = 0;
    pBlah[3] = AF_LINK;
    pBlah[4] = NET_RT_IFLIST;

    // use index of interface to get only its info
    if ( (pBlah[5] = if_nametoindex(p_szDeviceName)) == 0)
    {
      eprintf("%s interface not found.\n", p_szDeviceName);
      bRet = false;
    }
	

    if (sysctl(pBlah, 6, NULL, &tSize, NULL, 0) < 0)
    {
      eprintf("Unable to do initial sysctl(): %s\n", strerror(errno));
      bRet = false;
    }
    else
    {
      char *pBuff = new char[tSize];

      if (sysctl(pBlah, 6, pBuff, &tSize, NULL, 0) < 0)
      {
        eprintf("Unable to do second sysctl() w/ size: %u: %s\n", (unsigned) tSize, strerror(errno));
        bRet = false;
      }
      else
      {
        struct if_msghdr *pMsgHdr = (struct if_msghdr *) pBuff;
        struct sockaddr_dl *pSA = NULL;

        pSA = (struct sockaddr_dl *)(pMsgHdr + 1);
        unsigned char* szName = (unsigned char *)LLADDR(pSA);
        memcpy(m_pTapMac, szName, 6);
      }
    }
#endif

    CLOSESOCKET(sock);
  }

  return bRet;
}


bool TunnelMgr::readTunPkt(HANDLE p_hTun, tun_pkt_t &p_tPkt)
{
    bool bRet = false;

  // *GROAN* Let's assume we get the whole packet in 1 read... :-/
  if (NULL == p_tPkt.m_pData)
  {
    p_tPkt.m_uSize = IP_MAXPACKET;
    p_tPkt.m_uOffset = 0;
    p_tPkt.m_bComplete = false;
    p_tPkt.m_pData = new char[p_tPkt.m_uSize];
    memset(p_tPkt.m_pData, 0, p_tPkt.m_uSize);
  }

  int iErr = read(p_hTun, &(p_tPkt.m_pData[p_tPkt.m_uOffset]), p_tPkt.m_uSize - p_tPkt.m_uOffset);
  if (iErr <= 0
      && EAGAIN != errno
      && EINTR != errno)
  {
    dprintf("Unable to read Ethernet frame: %s\n", strerror(errno));
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

//TODO 
// THis reads packets in a re-entrant fashion.
bool TunnelMgr::readSocketPkt(HANDLE p_iFd, tun_pkt_t &p_tPkt)
{
  bool bRet = true;

  struct ip *pIpHdr = NULL;
  struct sockaddr_in tAddr;
  memset(&tAddr, 0, sizeof(tAddr));

  // If there is no data, then this is the first time we are reading this packet.
  if (NULL == p_tPkt.m_pData)
  {
    int iCount = 0;
    memset(&p_tPkt, 0, sizeof(p_tPkt));

    // Start off by just trying to get the max IP packet out there (65K).
    p_tPkt.m_pData = new char[IP_MAXPACKET];
    memset(p_tPkt.m_pData, 0, IP_MAXPACKET);

    socklen_t tLen = sizeof(tAddr);
    iCount = recvfrom(p_iFd, p_tPkt.m_pData, IP_MAXPACKET, 0, (struct sockaddr *) &tAddr, &tLen);

    if (iCount <= 0 && EAGAIN != errno)
    {
      dprintf("Unable to get header from socket %d: %s\n", p_iFd, strerror(errno));
      delete[] p_tPkt.m_pData;
      p_tPkt.m_pData = NULL;
      bRet = false;
    }
    // We need to get AT LEAST the IP header.
    else if ((int) sizeof(struct ip) > iCount)
    {
      dprintf("Unable to get IP header from socket.  Only got: %d bytes.\n", iCount);
      delete[] p_tPkt.m_pData;
      p_tPkt.m_pData = NULL;
      bRet = false;
    }
    // Now that we have the header, we can re-allocate the proper amount of space...
    // We do this because our queue can be large and wasted mem could become an issue.
    else
    {
      bRet = true;

      // The first chunk needs to be an IP header.
      pIpHdr = (struct ip *) p_tPkt.m_pData;

      // We know how much we received (iCount), so we know our offset.
      p_tPkt.m_uOffset = iCount;
      p_tPkt.m_uSize = ntohs(pIpHdr->ip_len);
      dprintf("readpkt offset:%u\n", (unsigned int)p_tPkt.m_uOffset);
      dprintf("readpkt size:%u\n", (unsigned int)p_tPkt.m_uSize);

      // Re-allocate the right size.
      char *pTemp = new char[p_tPkt.m_uSize];
      memset(pTemp, 0, p_tPkt.m_uSize);
      // Copy data from the old 65K buff to the new one,
      memcpy(pTemp, p_tPkt.m_pData, p_tPkt.m_uSize);
      delete[] p_tPkt.m_pData;
      p_tPkt.m_pData = pTemp;
      pIpHdr = (struct ip *) p_tPkt.m_pData;

      // Get the IP:port of the source of this packet
      p_tPkt.m_uIP = ntohl(tAddr.sin_addr.s_addr);
      p_tPkt.m_uPort = ntohs(tAddr.sin_port);
      {
        char szIP[16];
        net_itoa(p_tPkt.m_uIP, szIP);
        dprintf("readpkt IP:%s Port:%u\n", szIP, p_tPkt.m_uPort);		
      }

      // Are we done?
      if (iCount < (int) p_tPkt.m_uSize)
      {
        p_tPkt.m_bComplete = false;
      }
      else
      {
        p_tPkt.m_bComplete = true;
      }
    }
  }

  // If all is well, and we have more to do
  // NOTE: This could be a continuation from above, or from a 
  // prior call to this method.
  if (bRet && !p_tPkt.m_bComplete)
//      p_tPkt.m_uOffset > 0 && p_tPkt.m_uOffset < p_tPkt.m_uSize)
  {
    int iTemp = 0;

    // Read again from the socket, starting where we left off last time.
    iTemp = recvfrom(p_iFd, &(p_tPkt.m_pData[p_tPkt.m_uOffset]), (p_tPkt.m_uSize - p_tPkt.m_uOffset), 0, NULL, NULL);

    if (iTemp <= 0
        && EINTR != errno
        && EAGAIN != errno)
    {
      dprintf("Unable to read from socket %d: %s\n", p_iFd, strerror(errno));
      destroyPkt(p_tPkt);
      bRet = false;
    }
    // If we got data, update our offset, can call it quits for now.
    else if (iTemp > 0)
    {
      p_tPkt.m_uOffset += iTemp;
      bRet = true;
    }
  }

  if (p_tPkt.m_uOffset >= p_tPkt.m_uSize)
  {
    p_tPkt.m_bComplete = true;
  }

  // If we are done...
  if (bRet && p_tPkt.m_bComplete)//p_tPkt.m_uOffset == p_tPkt.m_uSize)
  {
    // The first part should ALWAYS be an IP header.
    struct ip *pIpHdr = (struct ip *) p_tPkt.m_pData;

    // Sanity check, is this the right version right?
    if (4 != pIpHdr->ip_v)
    {
      dprintf("Version of header is not 4 is '%d', aborting.\n", pIpHdr->ip_v);

      destroyPkt(p_tPkt);
      bRet = false;
    }
   }

  return bRet;
}


#endif /* _MSC_VER */
