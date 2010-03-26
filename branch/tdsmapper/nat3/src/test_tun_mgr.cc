
// Use BSD-specific variable naming

#ifndef __USE_BSD
#define __USE_BSD
#endif



#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#include <netinet/udp.h>
#endif
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "tun_in_ent.h"
#include "tun_out_ent.h"
#include "tun_mgr.h"
#include "types.h"
#include "log.h"

class TestTunnelMgr : public TunnelMgr
{
  // Member Variables
  private:

  // Methods
  public:
    TestTunnelMgr() {};
    virtual ~TestTunnelMgr() {};

    bool testMapIn();
    bool testMapOut();
    bool testCreateIP();
    bool testWritePkt();
    bool testReadPkt();
    bool testMakeTunnelKey();
};

bool TestTunnelMgr::testMapIn()
{
  bool bRet = false;

  TunnelInboundEntry *pEnt = new TunnelInboundEntry();
  tun_hdr_t tHdr;
  memset(&tHdr, 2, sizeof(tHdr));
  pEnt->addHdr(tHdr);
  pEnt->addHdr(tHdr);
  string sKey("blah");
  mapIn(sKey, pEnt);
  TunnelEntry *pRet = mapIn(sKey);
  if (NULL == pRet)
  {
    fprintf(stderr, "%s [%d] - Got NULL back from mapIn()!\n",
            __FILE__,
            __LINE__);
    bRet = false;
  }
  else if (pRet != pEnt)
  {
    fprintf(stderr, "%s [%d] - Unable to mapIn(): returned entry was not the same as input.\n",
            __FILE__,
            __LINE__);
    bRet = false;
  }
  else
  {
    fprintf(stdout, "testMapIn() PASSED\n");
    bRet = true;
  }

  return bRet;
}

bool TestTunnelMgr::testMapOut()
{
  bool bRet = false;

  TunnelOutboundEntry *pEnt = new TunnelOutboundEntry();
  tun_hdr_t tHdr;
  memset(&tHdr, 1, sizeof(tHdr));
  pEnt->addHdr(tHdr);
  pEnt->addHdr(tHdr);
  mapOut(1, pEnt);
  TunnelEntry *pRet = mapOut(1);
  if (NULL == pRet)
  {
    fprintf(stderr, "%s [%d] - Got NULL back from mapOut()!\n",
            __FILE__,
            __LINE__);
    bRet = false;
  }
  else if (pRet != pEnt)
  {
    fprintf(stderr, "%s [%d] - Unable to mapOut(): returned entry was not the same as input.\n",
            __FILE__,
            __LINE__);
    bRet = false;
  }
  else
  {
    fprintf(stdout, "testMapOut() PASSED\n");
    bRet = true;
  }

  return bRet;
}

bool TestTunnelMgr::testCreateIP()
{
  bool bRet = false;

  uint32_t uIP = createNewIP();
  uint32_t uIP2 = createNewIP();
  if ((uIP & getMask()) != getLocalNet())
  {
    fprintf(stderr, "%s [%d] - Unable to get local IP first time: %X (%X & %X) != %X\n",
            __FILE__,
            __LINE__,
            uIP,
            uIP,
            getMask(),
            getLocalNet());
    bRet = false;
  }
  else if ((uIP2 & getMask()) != getLocalNet())
  {
    fprintf(stderr, "%s [%d] - Unable to get local IP secind time: %u\n",
            __FILE__,
            __LINE__,
            uIP2);
    bRet = false;
  }
  else
  {
    fprintf(stdout, "testCreateIP() - PASSED\n");
    bRet = true;
  }

  return bRet;
}

bool TestTunnelMgr::testWritePkt()
{
  bool bRet = false;

  struct sockaddr_in tAddr;
  memset(&tAddr, 0, sizeof(tAddr));
  tAddr.sin_family = AF_INET;
  tAddr.sin_port = htons(9007);
  tAddr.sin_addr.s_addr = INADDR_ANY;//htonl(0x7F000001);

  struct sockaddr_in tRawAddr;
  memset(&tRawAddr, 0, sizeof(tRawAddr));
  tRawAddr.sin_family = AF_INET;
  tRawAddr.sin_port = 0;//htons(9007);//0;
  tRawAddr.sin_addr.s_addr = htonl(0x7F000001);
  int iHincl = 1;

  // - open a socket and bind to a port
  int iRecvFD = socket(AF_INET, SOCK_DGRAM, 0);
  int iSendFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (iRecvFD < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to create socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (iSendFD < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to create raw socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (0 != bind(iRecvFD, (struct sockaddr *) &tAddr, sizeof(tAddr)))
  {
    fprintf(stderr, "%s [%d] - Unable to bind to socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  if (0 != setsockopt(iSendFD, IPPROTO_IP, IP_HDRINCL, &iHincl, sizeof(iHincl)))
  {
    fprintf(stderr, "%s [%d] - Unable to set option for header inclusion: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (!setNonblocking(iRecvFD))
  {
    fprintf(stderr, "%s [%d] - Unable to set socket as non-blocking.\n",
            __FILE__,
            __LINE__);
  }
  else
  {
    // - try to make a header that will send to this port on localhost
    uint16_t uHeaderLen = sizeof(struct ip) + sizeof(struct udphdr);
    uint16_t uLen = uHeaderLen + 10;
    char *pBuff = new char[uLen];
    struct ip *pIpHdr = (struct ip *) pBuff;
    struct udphdr *pUdpHdr = (struct udphdr *) &(pBuff[sizeof(struct ip)]);

    memset(pBuff, 0, uLen);
    memcpy(&(pBuff[uLen - 10]), "0123456789", 10);

    pIpHdr->ip_v = 4;
    pIpHdr->ip_hl = sizeof(struct ip) / 4;
    pIpHdr->ip_len = htons(uLen);
    pIpHdr->ip_id = htons(2);
    pIpHdr->ip_ttl = 63;
    pIpHdr->ip_p = IPPROTO_UDP;
    pIpHdr->ip_src.s_addr = htonl(0x7F000001);
    pIpHdr->ip_dst.s_addr = htonl(0x7F000001);
    pIpHdr->ip_sum = checksum((uint16_t *) pBuff, uLen);

    pUdpHdr->uh_sport = htons(19091);
    pUdpHdr->uh_dport = htons(9007);
    pUdpHdr->uh_ulen = htons(uLen - sizeof(struct ip));
    pUdpHdr->uh_sum = checksum((uint16_t *) pUdpHdr, uLen - sizeof(struct ip));

    // - try readinf a packet and see if it is delivered proprtly and intact.
    tun_pkt_t tPkt;
    memset(&tPkt, 0, sizeof(tPkt));
    tPkt.m_uIP = (uint32_t) ntohl(pIpHdr->ip_dst.s_addr);
    tPkt.m_uPort = ntohs(pUdpHdr->uh_dport);
    tPkt.m_bComplete = true;
    tPkt.m_uSize = uLen;
    tPkt.m_pData = pBuff;
    fprintf(stdout, "\tGoing to send initial packet.\n");
    bRet = writePkt(iSendFD, tPkt);

    while (bRet && !tPkt.m_bComplete)
    {
      fprintf(stdout, "\tGoing to write %u bytes.\n", (unsigned) (tPkt.m_uSize - tPkt.m_uOffset));
      bRet = writePkt(iSendFD, tPkt);
    }

    char *pRecvBuff = new char[uLen];
    memset(pRecvBuff, 0, uLen);
    // - send to the socket
    fprintf(stdout, "\tGoing to recv %u bytes.\n", uLen);
    int iRecv = recvfrom(iRecvFD, pRecvBuff, uLen - uHeaderLen, 0, NULL, NULL);
    if (iRecv != (uLen - uHeaderLen))
    {
      fprintf(stderr, "%s [%d] - Unable to recv buffer from socket: %s\n",
              __FILE__,
              __LINE__,
              strerror(errno));
    }
    else
    {

      if (0 != memcmp(&(tPkt.m_pData[uHeaderLen]), pRecvBuff, uLen - uHeaderLen))
      {
        fprintf(stderr, "%s [%d] - Data read off socket differs from sent value.\n",
                __FILE__,
                __LINE__);
        bRet = false;
      }
      else
      {
        fprintf(stdout, "testWritePkt() - PASSED\n");
        bRet = true;
      }
    }

    delete[] pBuff;
  }

  // - close the socket.
  close(iRecvFD);
  close(iSendFD);

  return bRet;

  return bRet;
}

bool TestTunnelMgr::testReadPkt()
{
  bool bRet = false;

  // - open a socket abd bind to a port
  struct sockaddr_in tAddr;
  memset(&tAddr, 0, sizeof(tAddr));
  tAddr.sin_family = AF_INET;
  tAddr.sin_port = htons(9007);
  tAddr.sin_addr.s_addr = INADDR_ANY;//htonl(0x7F000001);

  struct sockaddr_in tRawAddr;
  memset(&tRawAddr, 0, sizeof(tRawAddr));
  tRawAddr.sin_family = AF_INET;
  tRawAddr.sin_port = 0;//htons(9007);//0;
  tRawAddr.sin_addr.s_addr = htonl(0x7F000001);
  int iHincl = 1;

  int iRecvFD = socket(AF_INET, SOCK_DGRAM, 0);
  int iSendFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (iRecvFD < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to create socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (iSendFD < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to create raw socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (0 != bind(iRecvFD, (struct sockaddr *) &tAddr, sizeof(tAddr)))
  {
    fprintf(stderr, "%s [%d] - Unable to bind to socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  if (0 != setsockopt(iSendFD, IPPROTO_IP, IP_HDRINCL, &iHincl, sizeof(iHincl)))
  {
    fprintf(stderr, "%s [%d] - Unable to set option for header inclusion: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (!setNonblocking(iRecvFD))
  {
    fprintf(stderr, "%s [%d] - Unable to set socket as non-blocking.\n",
            __FILE__,
            __LINE__);
  }
  else
  {
    // - create an encapsulated packet
    uint16_t uHeaderLen = sizeof(struct ip) + sizeof(struct udphdr);
    uint16_t uLen = 2 * uHeaderLen + 10;
    char *pBuff = new char[uLen];
    struct ip *pIpHdr = (struct ip *) pBuff;
    struct udphdr *pUdpHdr = (struct udphdr *) &(pBuff[sizeof(struct ip)]);

    memset(pBuff, 0, uLen);
    memcpy(&(pBuff[uLen - 10]), "0123456789", 10);

    pIpHdr->ip_v = 4;
    pIpHdr->ip_hl = sizeof(struct ip) / 4;
    pIpHdr->ip_len = htons(uLen);
    pIpHdr->ip_id = htons(2);
    pIpHdr->ip_ttl = 63;
    pIpHdr->ip_p = IPPROTO_UDP;
    pIpHdr->ip_src.s_addr = htonl(0x7F000001);
    pIpHdr->ip_dst.s_addr = htonl(0x7F000001);
    pIpHdr->ip_sum = checksum((uint16_t *) pBuff, uLen);

    pUdpHdr->uh_sport = htons(19091);
    pUdpHdr->uh_dport = htons(9007);
    pUdpHdr->uh_ulen = htons(uLen - sizeof(struct ip));
    pUdpHdr->uh_sum = checksum((uint16_t *) pUdpHdr, uLen - sizeof(struct ip));

    pIpHdr = (struct ip *) &(pBuff[uHeaderLen]);
    pUdpHdr = (struct udphdr *) &(pBuff[uHeaderLen + sizeof(struct ip)]);

    pIpHdr->ip_v = 4;
    pIpHdr->ip_hl = sizeof(struct ip) / 4;
    pIpHdr->ip_len = htons(uLen - uHeaderLen);
    pIpHdr->ip_ttl = 64;
    pIpHdr->ip_p = IPPROTO_UDP;
    pIpHdr->ip_src.s_addr = htonl(0x12345678);
    pIpHdr->ip_dst.s_addr = htonl(0x7F000001);
    pIpHdr->ip_sum = checksum((uint16_t *) pIpHdr, uLen - uHeaderLen);

    pUdpHdr->uh_sport = htons(9090);
    pUdpHdr->uh_dport = htons(9007);
    pUdpHdr->uh_ulen = htons(uLen - (uHeaderLen + sizeof(struct ip)));
    pUdpHdr->uh_sum = checksum((uint16_t *) pUdpHdr, uLen - (uHeaderLen + sizeof(struct ip)));

    // - send to the socket
    fprintf(stdout, "\tGoing to send %u bytes.\n", uLen);
    int iSent = sendto(iSendFD, pBuff, uLen, 0, (struct sockaddr *) &tRawAddr, sizeof(tRawAddr));
    if (iSent != uLen)
    {
      fprintf(stderr, "%s [%d] - Unable to send buffer to raw socket: %s\n",
              __FILE__,
              __LINE__,
              strerror(errno));
    }
    else
    {
      // - try readPkt() from the socket
      tun_pkt_t tPkt;
      memset(&tPkt, 0, sizeof(tPkt));
      fprintf(stdout, "\tGoing to receive initial packet.\n");
      bRet = readSocketPkt(iRecvFD, tPkt);

      while (bRet && !tPkt.m_bComplete)
      {
        fprintf(stdout, "\tGoing to receive %u bytes.\n", (unsigned) (tPkt.m_uSize - tPkt.m_uOffset));
        bRet = readSocketPkt(iRecvFD, tPkt);
      }

      if (0 != memcmp(tPkt.m_pData, &(pBuff[uHeaderLen]), uLen - uHeaderLen))
      {
        fprintf(stderr, "%s [%d] - Data read off socket differs from sent value.\n",
                __FILE__,
                __LINE__);
        bRet = false;
      }
      else
      {
        fprintf(stdout, "testReadPkt() - PASSED\n");
        bRet = true;
      }
    }

    delete[] pBuff;
  }

  // - close the socket.
  close(iRecvFD);
  close(iSendFD);

  return bRet;
}

bool TestTunnelMgr::testMakeTunnelKey()
{
  bool bRet = false;

  return bRet;
}

int main(int argc, char *argv[])
{
   char logfile[] = "stderr";
  open_log_file(logfile);
  TunnelMgr::getInstance().init(0x7f000001, NAT3_DEFAULT_PORT);
  TestTunnelMgr oMgr;

  if (!oMgr.init(0x7f000001, NAT3_DEFAULT_PORT))
  {
    fprintf(stderr, "%s [%d] - Unable to init manager, terminating...\n",
            __FILE__,
            __LINE__);
  }
  else if (!oMgr.testMapIn())
  {
    fprintf(stderr, "%s [%d] - Test failed, terminating...\n",
            __FILE__,
            __LINE__);
  }
  else if (!oMgr.testMapOut())
  {
    fprintf(stderr, "%s [%d] - Test failed, terminating...\n",
            __FILE__,
            __LINE__);
  }
  else if (!oMgr.testCreateIP())
  {
    fprintf(stderr, "%s [%d] - Test failed, terminating...\n",
            __FILE__,
            __LINE__);
  }
  else if (!oMgr.testReadPkt())
  {
    fprintf(stderr, "%s [%d] - Test failed, terminating...\n",
            __FILE__,
            __LINE__);
  }
  else if (!oMgr.testWritePkt())
  {
    fprintf(stderr, "%s [%d] - Test failed, terminating...\n",
            __FILE__,
            __LINE__);
  }

  return 0;
}
