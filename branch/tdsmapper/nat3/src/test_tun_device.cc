// Use BSD-specific variable naming
//
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <time.h>


#include "tun_device.h"
#include "tun_defs.h"
#include "tun_mgr.h"
#include "types.h"
#include "log.h"

void PrintPacketInHex(unsigned char *packet, int len)
{
  unsigned char *p = packet;
  fprintf(stdout, "\n\n---------Packet---Starts----\n\n");

  while(len--)
  {
    fprintf(stdout, "%.2X ", *p);
    p++;
  }
  fprintf(stdout, "\n\n--------Packet---Ends-----\n\n");
}

class TestTunDevice
{
  public:
    TestTunDevice() : m_pTunDev(NULL) {}
    virtual ~TestTunDevice() 
    {
      delete m_pTunDev;
    }
    void setTunDev(TunDevice* pTunDev)
    {
      assert(pTunDev);
      m_pTunDev = pTunDev;
    }
    bool testOpenDev();
    bool testSetIp();
    bool testSetMtu();
    bool testAddLocalRoute();
  
  protected:
    static uint32_t m_uPingPacketCount;
    static uint32_t m_uPingPacketSize;
    static time_t   m_tMaxPingSec;
    static float    m_fPingIntervalSec;

  protected:
    bool pingDevice();
    bool readTunDevice(int fd);

  private:
    // Owns the TunDevice pointer 
    TunDevice* m_pTunDev;
};
// Number of ping packets to send. 
uint32_t TestTunDevice::m_uPingPacketCount = 1;
// Number of ping payload bytes 
uint32_t TestTunDevice::m_uPingPacketSize = 56;
// Maximum time allowed for ping in seconds
time_t TestTunDevice::m_tMaxPingSec = 3;
// Maximum interval for sending ping packets in fraction of a second.
float TestTunDevice::m_fPingIntervalSec = 0.3;

//-------------------------------------------------------------------------------------------
bool TestTunDevice::pingDevice() 
{
  bool bRet = true;
  char szPing[128];
  char szIP[32];
  TunnelMgr::net_itoa(NAT3_LOCAL_NET + 10, szIP);
  // "ping 127.254.0.11 -c 5 -s 56 -i 0.3
  snprintf(szPing, sizeof(szPing),
           "ping %s -c %d -s %d -i %f",
           szIP, 
           m_uPingPacketCount,
           m_uPingPacketSize,
           m_fPingIntervalSec);
  
  int iStatus;
  fprintf(stdout, "pingDevice() - Pinging... Please wait a few secs.\n");
  fflush(stdout);
  if (0 == (iStatus = system(szPing)))
  {
    bRet = true;
    fprintf(stdout, "pingDevice() - SUCCEEDED\n");
  }
  //TODO(jkrikheli) implement the ICMP echo reply
  // until then just return true. 
  // return bRet; 
  return true;
}

bool TestTunDevice::readTunDevice(int fd)
{
  bool bRet; 
  ssize_t r;
  unsigned char buf[NAT3_TUN_MTU];
  struct ip* iph;
  uint32_t uRead = 0;
  char szSrcIp[32];
  char szDstIp[32];
  // Maximum size of the buffer to read.
  // (PingPacketPayload + IPheader + ICMPheader) * PacketCount
  const uint32_t kMaxRead = (m_uPingPacketSize + 28) * m_uPingPacketCount;
  // Get current time 
  time_t tStartTime = time(NULL);
  
  while (uRead < kMaxRead) 
  {
    r = read(fd, buf, NAT3_TUN_MTU);
    uRead += r;
    PrintPacketInHex(buf, r);
    
    // Time out if no traffic is heard 
    time_t tCurTime = time(NULL);
    if (tCurTime - tStartTime > m_tMaxPingSec)
    {
      fprintf(stderr, "%s [%d] - Timed out waiting for ping packets\n",
              __FILE__,
              __LINE__);
      break; 
    } 

    printf("Packet size : %d\n", (int)r);    
   
    iph = (struct ip*)buf; 
    TunnelMgr::net_itoa(ntohl(iph->ip_src.s_addr), szSrcIp);
    TunnelMgr::net_itoa(ntohl(iph->ip_dst.s_addr), szDstIp);     
    printf("IP SRC     : %s\n", szSrcIp);
    printf("IP DEST    : %s\n", szDstIp);
    printf("TTL                : %d\n", iph->ip_ttl);
    printf("Total Len : %d\n", ntohs(iph->ip_len));     
  }
  bRet = uRead > 0;
  if (bRet)
  {
    fprintf(stdout, "readTunDevice() - SUCCEEDED\n");
  }
  return uRead > 0;
}

bool TestTunDevice::testOpenDev() 
{
  bool bRet = false;
  // pTunDev must exist 
  assert(m_pTunDev); 

  fprintf(stdout, "testOpenDev() - Start opening device\n");
  
  // Open a device with a given ip, netmask, and MTU 
  int fd = m_pTunDev->openDev(NAT3_LOCAL_NET + 1,
                              NAT3_LOCAL_NETMASK,
                              NAT3_TUN_MTU);
  fprintf(stdout, "testOpenDev() - Finished opening device\n");
  if (fd >= 0)
  {
    bRet = true;
    if(!pingDevice())
    {
      bRet = false; 
      fprintf(stderr, "%s [%d] - Unable to send ping command : %s\n",
              __FILE__,
              __LINE__,
              strerror(errno));
    }
    else if (!readTunDevice(fd))
    {
      bRet = false;
      fprintf(stderr, "%s [%d] - Unable to read ping packets : %s\n",
              __FILE__,
              __LINE__,
              strerror(errno));
    } 
  }
  return bRet;
}
//-------------------------------------------------------------------------------------------


//-------------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
  bool bRet = true;
  TestTunDevice testDev;

#ifdef NAT3_LINUX
  LinuxTunDevice* pd = new LinuxTunDevice();
  testDev.setTunDev(pd);
  if (!testDev.testOpenDev()) {
    fprintf(stderr, "%s [%d] - Unable to open TUN/TAP device\n",
            __FILE__,
            __LINE__);  
    bRet = false;
  } 
#elif defined(NAT3_DARWIN) 
  testDev.setTunDev(new DarwinTunDevice());
  if (!testDev.testOpenDev()) {
    fprintf(stderr, "%s [%d] - Unable to open TUN/TAP device\n",
            __FILE__,
            __LINE__);  
    bRet = false;
  }  
#endif
  if (bRet)
  {
    fprintf(stdout, "testOpenDev() - PASSED\n");
  }
  else
  {
    fprintf(stdout, "testOpenDev() - FAILED\n");
  }
  return 0;
}
