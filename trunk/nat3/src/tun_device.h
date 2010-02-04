#ifndef _TUN_DEVICE_H
#define _TUN_DEVICE_H

#include "tun_defs.h"
#include <string>
//#define NAT3_DARWIN 1

// Implements default TUN/TAP functionality
class TunDevice 
{
  public:
    TunDevice();
    virtual ~TunDevice();
    virtual int openDev(uint32_t uLocalIp, 
                        uint32_t uNetMask, 
                        uint32_t uMTU) = 0;
  
  // variables
  protected:
    // IP address of the device 
    uint32_t m_uLocalIp;
    // Interface netmask 
    uint32_t m_uNetMask;
    // Device MTU
    uint32_t m_uMTU;
    // Device file descriptor
    int m_iFd;
    // Device name 
    char m_szDevName[256];

  // methods
  protected:
    virtual bool setIp();
    virtual bool setMtu();
    virtual bool addLocalRoute() = 0;
};

#ifdef NAT3_LINUX
class LinuxTunDevice : public TunDevice
{
  public:
    LinuxTunDevice();
    virtual ~LinuxTunDevice();
    virtual int openDev(uint32_t uLocalIp,
                        uint32_t uNetMask,
                        uint32_t uMTU);
  protected:
    virtual bool setIp();
    virtual bool setMtu();
    virtual bool addLocalRoute();
};

#elif defined(NAT3_DARWIN)

class DarwinTunDevice : public TunDevice
{
  public:
    DarwinTunDevice();
    virtual ~DarwinTunDevice();
    virtual int openDev(uint32_t uLocalIp,
                        uint32_t uNetMask,
                        uint32_t uMTU);
  protected:
    virtual bool setIp();
    virtual bool setMtu();
    virtual bool addLocalRoute();
};

#endif // NAT3_LINUX

#endif // _TUN_DEVICE_H
