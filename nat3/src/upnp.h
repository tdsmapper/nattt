#ifndef _UPNP_H
#define _UPNP_H

#define LOCALIP1  "10."
#define LOCALIP2  "192.168."
#define LOCALIP3  "172."
#define LOCALIP3BEGIN 16
#define LOCALIP3END   31

#define LEN_ADDR_STR 16

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

class UPnP
{
   private:
      // Member variables
      int m_iPort;
      char m_szAddress[LEN_ADDR_STR];
      struct UPNPUrls urls;
      struct IGDdatas data;


      // Member functions
      int isPrivateAddress(char *addr);
      int getLocalInterfaceAddress(char *addr);
     
   public:
      UPnP();
      ~UPnP();
      int init(int port);
      int forward_port();
      int remove_forwarding();
};


#endif
