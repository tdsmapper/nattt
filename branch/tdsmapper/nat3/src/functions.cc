#ifdef _MSC_VER
   #include <Winsock2.h>
   #include <Windows.h>
   #include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "functions.h"
#include "types.h"

#ifndef _MSC_VER

int GetLastError()
{
  return errno;
}

bool GetInterfaceMacAddress(char *pIface, unsigned char cMacAddr[])
{
   bool bRet = false;
   int sockfd;
   struct ifreq sIfReq;

   // The kernel does not support the required ioctls
#ifndef SIOCGIFADDR
   eprintf("The kernel does not support SIOCGIFADDR\n");
   return -1;
#endif

   strncpy(sIfReq.ifr_name, pIface, IF_NAMESIZE);
   sockfd = socket(PF_INET, SOCK_STREAM, 0);
   if (sockfd < 0)
   {
      printf("Socket failed %d\n", errno);
      bRet = false;
   }
   else if (ioctl(sockfd, SIOCGIFHWADDR, &sIfReq) != 0)
   {
      printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
      close(sockfd);
      bRet = false;
   }
   else
   {
      memcpy(cMacAddr, sIfReq.ifr_ifru.ifru_hwaddr.sa_data, 6);
      close(sockfd);
      bRet = true;
   }
   return bRet;
}
#else

/* The pIface name is the GUID name of the adapter. Returns false if Macaddr is unusable */
bool GetInterfaceMacAddress(char *szAdapterName, unsigned char cMacAddr[])
{
  bool bRet = false;
  PIP_ADAPTER_INFO pAdapterInfo;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD dwRetVal = 0;
  UINT i;

  ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
  pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
  if (pAdapterInfo == NULL)
  {
    printf("Error allocating memory needed to call GetAdaptersinfo\n");
    bRet = false;
  }

  /* Make an initial call to GetAdaptersInfo to get 
  the necessary size into the ulOutBufLen variable */
  else if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
  {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) 
    {
      printf("Error allocating memory needed to call GetAdaptersinfo\n");
      bRet = false;
    }
    /* Get adapters Info and search for the MAC address of the adapter */
    else if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
    {
      bRet = false;
      pAdapter = pAdapterInfo;
      while (pAdapter)
      {
        if (strstr(szAdapterName, pAdapter->AdapterName))
        {
          memcpy(cMacAddr, pAdapter->Address, MACADDRSIZE);
          bRet = true;
          break;
        }
        pAdapter = pAdapter->Next;
      }
      free(pAdapterInfo);
    }
    else
    {
      printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);    
      free(pAdapterInfo);
    }
  }
  else
  {
    printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);    
  }

  return bRet;
} 

#endif /* _MSC_VER */

/* Functions common to both Windows and *NIX */
// Simple helper.
bool net_itoa(uint32_t p_uIP, char *p_szOutput)
{
  bool bRet = false;

  if (NULL == p_szOutput)
  {
    eprintf("NULL output buffer.\n");
  }
  else
  {
    int iA = (p_uIP >> 24) & 0xFF;
    int iB = (p_uIP >> 16) & 0xFF;
    int iC = (p_uIP >> 8) & 0xFF;
    int iD = p_uIP & 0xFF;

    sprintf(p_szOutput, "%d.%d.%d.%d", iA, iB, iC, iD);
    bRet = true;
  }

  return bRet;
}
