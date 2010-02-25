#ifdef _MSC_VER
  #include <Winsock2.h>
  #include <Ws2tcpip.h>
  #include <Windows.h>
#else
  #include <pthread.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resolver.h"
#include "tun_mgr.h"
#include "config_file.h"
#include "functions.h"
#include "tun_defs.h"

/* Some globals. Avoidable? */
uint32_t IPADDR;

#ifdef _MSC_VER
  DWORD dwMajorVersion = -1, dwMinorVersion = -1;
#endif

#if 0
// shamelessly stolen/adapted from the D
bool locate_resolver(uint32_t &res) {
    FILE *f;
    char buf[BUFSIZ];
    unsigned a, b, c, d;

    if ((f = fopen("/etc/resolv.conf", "r")) == NULL) {
        fprintf(stderr, "cannot open resolv.conf");
        return false;
    }

    while (fgets(buf, BUFSIZ, f) != NULL)
        if (sscanf(buf, "nameserver %u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            res = (unsigned)a << 24 | b << 16 | c << 8 | d;
            fclose(f);
            return true;
        }

    fclose(f);
    fprintf(stderr, "couldn't find nameserver line in resolv.conf");
    return false;
}
#endif

bool locate_resolver(ConfigFile &f, uint32_t &res) {
  const string *res_string = f.get("resolver");

  if (res_string == NULL) {
    fprintf(stderr, "No resolver given in configuration file\n");
    return false;
  }

  struct in_addr a;
  if (!inet_pton(AF_INET, res_string->c_str(), &a)) {
    fprintf(stderr, "%s is not a valid IP address\n", res_string->c_str());
    return false;
  }

  res = ntohl(a.s_addr);
  return true;
}

/* Common function called from both Windows and Linux/BSD wrapper functions */
int resolver_main(uint32_t ip) {
  Resolver r;
  r.init(ip, 53);

  if (!r.listen())
    fprintf(stderr, "There was a problem starting the resolver\n");
  return NULL;
}


#ifdef _MSC_VER

DWORD WINAPI windows_resolver_wrapper(LPVOID lParam)
{
	return (DWORD)resolver_main(IPADDR);
}

#else

void *linux_bsd_resolver_wrapper(void *arg)
{
	return (void*)resolver_main(IPADDR);
}

#endif

#ifdef _MSC_VER
bool getWindowsVersion()
{
  bool bRet = false;

  /* Check the OS version */
  OSVERSIONINFO osvi;
  ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
  if (GetVersionEx(&osvi))
  {
    dwMajorVersion = osvi.dwMajorVersion;
    dwMajorVersion = osvi.dwMinorVersion;
    bRet = true;
  }

  return bRet;
}
#endif


void* _spawnResolver(ConfigFile &f) //changed from pthread_t
{
  if (!locate_resolver(f, IPADDR))
	  return NULL;

#ifndef _MSC_VER
  // create and launch the resolver thread
  pthread_t *ret = new pthread_t;
  if (pthread_create(ret, NULL, linux_bsd_resolver_wrapper, NULL) != 0) {
	  fprintf(stderr, "There was an error creating the resolver thread\n");
	  delete ret;
	  ret = NULL;
  }
#else
   HANDLE ret = NULL;
   ret = CreateThread(
			NULL,                      // default security attributes
			0,                         // use default stack size 
			windows_resolver_wrapper,  // thread function name
			NULL,                // argument to thread function 
			0,                         // use default creation flags 
			0);
#endif

  return ret;
}

bool get_tap_options(ConfigFile &f, uint32_t &tapAddr, uint32_t &tapMask)
{
  const string *tempString = f.get("tapnetaddr");
  struct in_addr addr;
  memset(&addr, 0, sizeof(addr));

  // Get the address first
  if (NULL != tempString)
  {
    if (!inet_pton(AF_INET, tempString->c_str(), &addr))
    {
      fprintf(stderr, "tapnetaddr is not a valid IP address\n");
      return false;
    }
    else if (0 == addr.s_addr)
    {
      fprintf(stderr, "tapnetaddr cannot be 0\n");
      return false;
    }
    tapAddr = ntohl(addr.s_addr);

    // Get net mask
    const string *tempString = f.get("tapnetmask");
    if (NULL != tempString)
    {
      memset(&addr, 0, sizeof(addr));
      if (!inet_pton(AF_INET, tempString->c_str(), &addr))
      {
        fprintf(stderr, "tapnetmask is not a valid net mask\n");
        return false;
      }
      else if (0 == addr.s_addr)
      {
        fprintf(stderr, "tapnetmask cannot be 0\n");
        return false;
      }
      tapMask = ntohl(addr.s_addr);
    }
    else
    {
      fprintf(stderr, "Found tapnetaddr but not tapnetmask\n");
      return false;
    }
  }
  else
  {
    tapMask = NAT3_LOCAL_NETMASK;
    tapAddr = NAT3_LOCAL_NET;
  }
  return true;
}

bool get_options(ConfigFile &f, uint32_t &ip_addr, uint16_t &port, uint32_t &tapAddr, uint32_t &tapMask, bool &bBridge) {
  const string *ip_str = f.get("ip");
  if (ip_str == NULL) {
    fprintf(stderr, "No IP address found in configuration file\n");
    return false;
  }

  struct in_addr ip;
  if (!inet_pton(AF_INET, ip_str->c_str(), &ip)) {
    fprintf(stderr, "Unable to parse %s as IP address\n", ip_str->c_str());
    return false;
  }
  ip_addr = ntohl(ip.s_addr);
  const string *port_str = f.get("port");
  if (port_str == NULL) {
    fprintf(stderr, "No port found in configuration file\n");
    return false;
  }
  int p = atoi(port_str->c_str());
  if (p < 0 || p > 65535) {
    fprintf(stderr, "Port %s is not valid\n", port_str->c_str());
    return false;
  }
  port = p;

  /* The network address and mask of the TUN/TAP device. Try and get both the mask and the address (optional)*/
  if (!get_tap_options(f, tapAddr, tapMask))
  {
    return false;
  }

  /* Do we need to bridge */
  bBridge = false;
  const string *bridgeString = f.get("bridge");
  if (!stricmp(bridgeString->c_str(), "on"))
  {
    bBridge = true;
  }
  
  return true;
}

int main(int argc, char *argv[])
{
  ConfigFile f;
  string config_file = "/etc/nat3.conf";
  if (argc > 1)
    config_file = argv[1];

  if (!f.load(config_file)) {
    fprintf(stderr, "Error loading configuration file: %s\n", f.error());
    return 2;
  }

  /* Windows WSAStartup - before resolver or tun_mgr */
#ifdef _MSC_VER
  if (!getWindowsVersion())
  {
    eprintf("Couldnt get Windows version\n");
    return 3;
  }

  if (!WSACleanup())
  {
    eprintf("Cleanup failed! %d\n", GetLastError());
  }

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
  {
    eprintf("win_tun_mgr: WSAStartup failed %d!\n", GetLastError());
  }
#endif /* _MSC_VER */
    
  uint32_t ip;
  uint16_t port;
  uint32_t tapNetmask, tapAddr;
  bool bBridge;
  if (!get_options(f, ip, port, tapAddr, tapNetmask, bBridge))
    return 1;
  if (_spawnResolver(f) == NULL)
    return 1;

  TunnelMgr &mgr = TunnelMgr::getInstance();
  mgr.init(ip,
    port,
    tapAddr,
    tapNetmask,
    bBridge,
    TUN_MGR_MAX_LRU,
    TUN_MGR_MAX_LRU,
    TUN_MGR_MAX_PKT_QUEUE,
    TUN_MGR_MAX_PKT_QUEUE);
  mgr.listen();

#ifdef _MSC_VER
  if (WSACleanup())
  {
    eprintf("WSACleanup failed with %d\n", GetLastError());
  }
#endif /* _MSC_VER */

  return 0;
}
