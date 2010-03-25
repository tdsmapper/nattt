#ifdef _MSC_VER
  #include <Winsock2.h>
#else
  #include <arpa/inet.h>
  #include <net/if.h>
  #include <netinet/in.h>
  #include <netinet/ip.h>
  #include <sys/ioctl.h>
  #include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "tun_defs.h"
#include "tun_device.h"

using namespace std;

//TODO(jkrikheli) move net_itoa() to a common file
#include "tun_mgr.h"  // only for net_itoa()
#include "types.h"
#include "functions.h"

// This must appear after tun_device.h which defines NAT3_LINUX
#ifdef NAT3_LINUX
  #include <linux/if_tun.h>
#endif


TunDevice::TunDevice() : m_uLocalIp(0), m_uNetMask(0), m_uMTU(0),
  m_iFd(-1) 
{
  memset(m_szDevName, 0, sizeof(m_szDevName));
}

TunDevice::~TunDevice() 
{

}

int TunDevice::openDev(uint32_t uLocalIp,
                       uint32_t uNetMask,
                       uint32_t uMTU) 
{
  return -1;
}


// LocalIp is the actual IP address of the TUN interface
bool TunDevice::setIp()
{
  bool bRet = false;
  char szIfconfigCall[256];
  char szIP[32], szNetmask[32];

  // Set the IP address.   
  net_itoa(m_uLocalIp, szIP);
  net_itoa(m_uNetMask, szNetmask);

  // Bring up the TUN device
  // ex: ifconfig tun0 127.254.0.1 127.254.0.1 netmask 255.255.0.0
  snprintf(szIfconfigCall, sizeof(szIfconfigCall),
          "ifconfig %s %s %s netmask %s",
          m_szDevName,
          szIP,
          szIP,
          szNetmask);
  
  // Execute the szIfconfigCall 
  int iStatus;
  if (0 == (iStatus = system(szIfconfigCall))) {
    bRet = true;
  }

  return bRet;
}

// Returns true on success
bool TunDevice::setMtu()
{
  bool bRet = false; 
  char szIfconfigCall[256];
  // Set the MTU of the device
  snprintf(szIfconfigCall, sizeof(szIfconfigCall),
           "ifconfig %s mtu %u",
           m_szDevName,
           m_uMTU);
  int iStatus; 
  if (0 == (iStatus = system(szIfconfigCall)))
  {
    bRet = true;
  }

  return bRet;
}

//------------------------------------------------------------------------
// LinuxTunDevice definitions 

#ifdef NAT3_LINUX

LinuxTunDevice::LinuxTunDevice()
{
}

LinuxTunDevice::~LinuxTunDevice()
{
}
// Return -1 on error
// Assumes valid values for IP, NetMask, & DevName
int LinuxTunDevice::openDev(uint32_t uLocalIp,
                            uint32_t uNetMask,
                            uint32_t uMTU)
{
  // File descriptor for the TUN interface
  int fd = -1;
  struct ifreq ifr;
  
  m_uLocalIp = uLocalIp;
  m_uNetMask = uNetMask;
  m_uMTU = uMTU;

  // open the tun device for reading
  fd = open(LINUX_TUN_DEVICE_PATH, O_RDONLY);
  
  if (fd >= 0)
  {
    memset(&ifr, 0, sizeof(ifr));

    // IFF_TUN   - Open a TUN device
    // IFF_NO_PI - Do not provide packet information
    // IFF_ONE_QUEUE - Only use the /tun/tap queue.
    //                 Do not use the network device send queue.

    // TODO(jkrikheli) Check portability of the flags.
    // create the interface

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_ONE_QUEUE;
    int iRes = ioctl(fd, TUNSETIFF, &ifr); 
    if (iRes >= 0)
    {
      // store the actual Device name
      snprintf(m_szDevName, sizeof(m_szDevName),
               ifr.ifr_name);
      if (!strlen(m_szDevName))
      {
        fprintf(stderr, 
                "%s [%d] - Failed to get device interface for (%s): %s\n",
            __FILE__,
            __LINE__,
            LINUX_TUN_DEVICE_PATH,
            strerror(errno));
        fd = -1;
      }
      // set IP address and bring up the device 
      else if (!setIp())
      {
        fd = -1;
        fprintf(stderr, "%s [%d] - Unable to set IP address on (%s): %s\n",
                __FILE__,
                __LINE__,
                LINUX_TUN_DEVICE_PATH,
                strerror(errno));
      }
      else if (!setMtu()) // Set device MTU
      {
        fd = -1;
        fprintf(stderr,
                "%s [%d] - Unable to set MTU on (%s): %s\n",
                 __FILE__,
                 __LINE__,
                 m_szDevName,
                 strerror(errno));
      }
      else if (!addLocalRoute()) // Set up local routes
      {
        fd = -1;
        fprintf(stderr,
                "%s [%d] - Unable to add local route on device (%s): %s\n",
                __FILE__,
                __LINE__,
                LINUX_TUN_DEVICE_PATH,
                strerror(errno));
      }

    }
    else
    {
      fprintf(stderr, 
              "%s [%d] - Unable to execute ioctl on device (%s): %s\n",
              __FILE__,
              __LINE__,
              LINUX_TUN_DEVICE_PATH,
              strerror(errno));

    }

  }
  else
  {
    fprintf(stderr, "%s [%d] - Unable to open TUN/TAP device (%s): %s\n",
            __FILE__,
            __LINE__,
            LINUX_TUN_DEVICE_PATH,
            strerror(errno));
  }

  // return the file descriptor for the TUN interface
  return fd;  
}

bool LinuxTunDevice::setIp()
{
  return TunDevice::setIp();
}

bool LinuxTunDevice::setMtu()
{
  return TunDevice::setMtu();
}

bool LinuxTunDevice::addLocalRoute()
{
  bool bRet = false; 
  char szIpRouteCall[256];
  // ip route add table local 127.254.0.0/16 dev tun0
  snprintf(szIpRouteCall, sizeof(szIpRouteCall),
           "ip route add table local %s dev %s",
           NAT3_IP_ROUTE_PREFIX,
           m_szDevName);

  bool iStatus = 0;
  if(0 == (iStatus = system(szIpRouteCall)))
  {
    bRet = true;  
  }
  return bRet;  
}

#elif defined(NAT3_DARWIN) 
//----------------------------------------------------------------------
// DarwinTunDevice definitions
DarwinTunDevice::DarwinTunDevice()
{
}

DarwinTunDevice::~DarwinTunDevice()
{
}

int DarwinTunDevice::openDev(uint32_t uLocalIp,
                             uint32_t uNetMask,
                             uint32_t uMTU)
{
  // File descriptor for the TUN interface
  int fd = -1;
  int i;
  char szDevicePath[256];

  m_uLocalIp = uLocalIp;
  m_uNetMask = uNetMask;
  m_uMTU = uMTU;

  // Try successively opening devices until we find a free one.
  for (i = 0; i < MAX_TUN_OPEN_TRY; i++)
  {
    snprintf(szDevicePath, sizeof(szDevicePath), "/dev/tun%d", i);
    if ((fd = open(szDevicePath, O_RDONLY)) >= 0)
    {
      // We found an available device
      break;
    }
  }

  if (fd >= 0)
  {
    sprintf(m_szDevName, "tun%d", i);
    if (!strlen(m_szDevName))
    {
      fprintf(stderr,
              "%s [%d] - Failed to get device interface for (%s): %s\n",
          __FILE__,
          __LINE__,
          LINUX_TUN_DEVICE_PATH,
          strerror(errno));
      fd = -1;
    }
    // set IP address and bring up the device
    else if (!setIp())
    {
      fd = -1;
      fprintf(stderr, "%s [%d] - Unable to set IP address on (%s): %s\n",
              __FILE__,
              __LINE__,
              LINUX_TUN_DEVICE_PATH,
              strerror(errno));
    }
    else if (!setMtu()) // Set device MTU
    {
      fd = -1;
      fprintf(stderr,
              "%s [%d] - Unable to set MTU on (%s): %s\n",
               __FILE__,
               __LINE__,
               m_szDevName,
               strerror(errno));
    }
    else if (!addLocalRoute()) // Set up local routes
    {
      fd = -1;
      fprintf(stderr,
              "%s [%d] - Unable to add local route on device (%s): %s\n",
              __FILE__,
              __LINE__,
              LINUX_TUN_DEVICE_PATH,
              strerror(errno));
    }
  }      
  else
  {
    fprintf(stderr, "%s [%d] - Unable to find free TUN device : %s\n",
           __FILE__,
           __LINE__,
           strerror(errno));
  }
  return fd;
}

bool DarwinTunDevice::setIp()
{
  return TunDevice::setIp();
}

bool DarwinTunDevice::setMtu()
{
  return TunDevice::setMtu();
}

bool DarwinTunDevice::addLocalRoute()
{
  return true;
}

#endif // NAT3_LINUX

