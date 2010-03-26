#ifdef _MSC_VER
  #include <Winsock2.h>
  #include <Windows.h>
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <unistd.h>
  #include <netinet/ip.h>
  #include <netinet/ip_icmp.h>
  #include <netinet/udp.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "tun_defs.h"
#include "tun_mgr.h"
#include "types.h"
#include "functions.h"
#include "log.h"

#ifdef _MSC_VER
  #pragma pack(1)
  typedef struct
  {
    uint8_t m_uType;
    uint8_t m_uCode;
    uint16_t m_uChecksum;
    uint16_t m_uID;
    uint16_t m_uSeq;
    uint32_t m_uData;
  }  tun_icmp_pkt_t;
#else
  typedef struct
  {
    uint8_t m_uType;
    uint8_t m_uCode;
    uint16_t m_uChecksum;
    uint16_t m_uID;
    uint16_t m_uSeq;
    uint32_t m_uData;
  } __attribute__((__packed__)) tun_icmp_pkt_t;
#endif

int main(int argc, char *argv[])
{
   char logfile[] = "stderr";
  open_log_file(logfile);
  char pBuff[20 + 12 + 52];
  uint16_t uLen = 20 + 12 + 52;
  struct ip *pIP = (struct ip *) pBuff;
//  tun_icmp_pkt_t *pICMP = (tun_icmp_pkt_t *) &(pBuff[20]);
  struct icmp *pRealICMP = (struct icmp *) &(pBuff[20]);
  memset(pBuff, 0, uLen);

  uint32_t uDstIP = htonl(0x7F000001);
  if (argc > 1)
  {
    uint32_t uTmp = inet_addr(argv[1]);
    if (INADDR_NONE == uTmp)
    {
      fprintf(stderr, "IP address '%s' is malformed\n", argv[1]);
    }
    else
    {
      uDstIP = uTmp;
    }
  }

  struct sockaddr_in tBindAddr;
  memset(&tBindAddr, 0, sizeof(tBindAddr));
  tBindAddr.sin_family = AF_INET;
  tBindAddr.sin_addr.s_addr = INADDR_ANY;
  tBindAddr.sin_port = htons(100);

  int iFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (iFD < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to open outbound socket: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
  else if (bind(iFD, (struct sockaddr *) &tBindAddr, sizeof(tBindAddr)) < 0)
  {
    fprintf(stderr, "%s [%d] - Unable to bind: %s\n",
            __FILE__,
            __LINE__,
            strerror(errno));
  }
/*
*/
  else
  {
    struct sockaddr_in tAddr;
    memset(&tAddr, 0, sizeof(tAddr));
    tAddr.sin_family = AF_INET;
    tAddr.sin_port = htons(100);
    tAddr.sin_addr.s_addr = uDstIP;
//    tAddr.sin_addr.s_addr = htonl(0x7f000001);

    pIP->ip_v = 4;
    pIP->ip_hl = sizeof(struct ip) / 4;
    pIP->ip_len = htons(uLen);
    pIP->ip_ttl = 64;
    pIP->ip_p = IPPROTO_ICMP;
    pIP->ip_src.s_addr = htonl(0x7F000001);
    pIP->ip_dst.s_addr = uDstIP;

//    pICMP->m_uType = ICMP_ECHO;
//    pICMP->m_uID = 0x17e0;//1337;
    pRealICMP->icmp_type =ICMP_ECHO;
    pRealICMP->icmp_id = 0x17e0;//1337;
    for (int i = 0; i < 10; i++)
    {
      pRealICMP->icmp_seq = htons(i);

      pRealICMP->icmp_cksum = 0;
/*
      pICMP->m_uSeq = (uint16_t) i;
      pICMP->m_uData = (uint32_t) i;

      pICMP->m_uChecksum = 0;
*/
      pIP->ip_sum = 0;

//      pICMP->m_uChecksum = TunnelMgr::checksum((uint16_t *) pICMP, uLen - 20);
      pRealICMP->icmp_cksum = TunnelMgr::checksum((uint16_t *) pRealICMP, uLen - 20);
      pIP->ip_sum = TunnelMgr::checksum((uint16_t *) pBuff, uLen);

      if (uLen != sendto(iFD, pBuff, uLen, 0, (struct sockaddr *) &tAddr, sizeof(tAddr)))
      {
        fprintf(stderr, "%s [%d] - Unable to send to socket: %s\n",
                __FILE__,
                __LINE__,
                strerror(errno));
      }
      else
      {
        printf("Pinging %08X - %d\n", ntohl(uDstIP), i);
      }

      // Sleep 1 second
#ifdef _MSC_VER
      Sleep(1000);
#else
      sleep(1);
#endif
    }

    for (int j = 0; j < 10; j++)
    {
      socklen_t tLen = 0;
      memset(&tAddr, 0, sizeof(tAddr));
      if (uLen != recvfrom(iFD, pBuff, uLen, 0, (struct sockaddr *) &tAddr, &tLen))
      {
        fprintf(stderr, "%s [%d] - Unable to recvfrom socket: %s\n",
                __FILE__,
                __LINE__,
                strerror(errno));
      }
      else
      {
//        printf("Recv from %X - %d\n", ntohl(pIP->ip_src.s_addr), ntohl(pICMP->m_uData));
        printf("Recv from %X - %d\n", ntohl(pIP->ip_src.s_addr), ntohl(pRealICMP->icmp_seq));
      }
    }

    CLOSESOCKET(iFD);
  }

  return 0;
}
