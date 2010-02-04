#include "upnp.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

UPnP::UPnP(): m_iPort(0)
{
}

UPnP::~UPnP()
{
   remove_forwarding();
}

int UPnP::isPrivateAddress(char *addr)
{
   int ret = 0;
   if ((strstr(addr, LOCALIP1) == addr) ||
       (strstr(addr, LOCALIP2) == addr))
   {
      ret = 1;
   }
   else // If it is a 172.16-172.31 address
   {
      if ((strstr(addr, LOCALIP3) == addr))
      {
         int part1, part2;
         if (sscanf(addr, "%d.%d", &part1, &part2))
         {
            if (part2 >= LOCALIP3BEGIN && part2 <= LOCALIP3END)
            {
               ret = 1;
            }
         }
      }
   }
   return ret;
}

int UPnP::getLocalInterfaceAddress(char *addr)
{
   int found = 0;
   char* addrToTest = NULL;

   struct ifaddrs *ifap;
   if (getifaddrs(&ifap) == 0) 
   {
      struct ifaddrs *p;
      for (p = ifap; p; p = p->ifa_next) 
      {
         if (p->ifa_addr->sa_family == AF_INET) 
         {
            addrToTest = inet_ntoa(((struct sockaddr_in *)p->ifa_addr)->sin_addr);
            if (isPrivateAddress(addrToTest))
            {
               found = 1;
               break;
            }
         }
      }
      freeifaddrs(ifap);
   }
   return found;
}

int UPnP::init(int port)
{
   int ret = 0;
   if (getLocalInterfaceAddress(m_szAddress))
   {
      m_iPort = port;

      struct UPNPDev *devlist;
      struct UPNPDev *dev;
      char *descXML;
      int descXMLsize = 0;
      memset(&urls, 0, sizeof(struct UPNPUrls));
      memset(&data, 0, sizeof(struct IGDdatas));
      devlist = upnpDiscover(2000, 0, 0, 0);
      if (devlist)
      {
         dev = devlist;
         while (dev)
         {
            if (strstr (dev->st, "InternetGatewayDevice")) // See if the device is an IGD
            {
               break;
            }
            dev = dev->pNext;
         }
         if (!dev)
         {
            dev = devlist; /* defaulting to first device */
         }

         descXML = (char*)miniwget(dev->descURL, &descXMLsize);
         if (descXML)
         {
            parserootdesc (descXML, descXMLsize, &data);
            free (descXML); descXML = 0;
            GetUPNPUrls (&urls, &data, dev->descURL);
            ret = 1;
         }
         freeUPNPDevlist(devlist);
      }
   }
   return ret;
}

int UPnP::forward_port()
{
   int ret = 1;
   char port_str[16];
   int r;
   if (m_iPort == 0)
   {
      ret = 0;
   }
   else if (m_iPort == -1)
   {  
      // port removal alreadu done
   }
   else
   {
      sprintf(port_str, "%d", m_iPort);
      r = UPNP_AddPortMapping(urls.controlURL, data.servicetype,
            port_str, port_str, m_szAddress, 0, "TCP", 0);
      if (r == 0)
      {
         printf("Port Forwarding failed (%s, %s, %s) failed. You may need to do port forwarding manually.\n", port_str, port_str, m_szAddress);
         ret = 0;
      }
      else
      {
         ret = 1;
         m_iPort = -1;
      }
   }
   return ret;
}

int UPnP::remove_forwarding()
{
   int ret = 0;
   char port_str[16];
   int t;
   if(m_iPort == 0)
   {
      ret = 0;
   }
   else
   {
      int r = 0;
      sprintf(port_str, "%d", m_iPort);
      r = UPNP_DeletePortMapping(urls.controlURL, data.servicetype, port_str, "TCP", 0);
      if (r == 0)
      {
         printf("Port Forwarding removal failed (%s) failed\n", port_str);  
         ret = 0;
      }
      else
      {
         ret = 1;
      }
   }
}
