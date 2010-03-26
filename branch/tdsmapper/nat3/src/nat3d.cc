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
#include "log.h"
#include "resolver.h"
#include "tun_mgr.h"
#include "config_file.h"
#include "functions.h"
#include "tun_defs.h"
#include "pcap_arp_handler.h"
#include "log.h"

/* Some globals. Avoidable? */
uint32_t RESOLVERADDR;
PcapArpHandler PARP;

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
        eprintf( "cannot open resolv.conf");
        return false;
    }

    while (fgets(buf, BUFSIZ, f) != NULL)
        if (sscanf(buf, "nameserver %u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            res = (unsigned)a << 24 | b << 16 | c << 8 | d;
            fclose(f);
            return true;
        }

    fclose(f);
    eprintf( "couldn't find nameserver line in resolv.conf");
    return false;
}
#endif

bool locate_resolver(ConfigFile &f, uint32_t &res) {
  const string *res_string = f.get("resolver");

  if (res_string == NULL) {
    eprintf( "No resolver given in configuration file\n");
    return false;
  }

  struct in_addr a;
  if (!inet_pton(AF_INET, res_string->c_str(), &a)) {
    eprintf( "%s is not a valid IP address\n", res_string->c_str());
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
    eprintf( "There was a problem starting the resolver\n");
  return NULL;
}


#ifdef _MSC_VER

DWORD WINAPI windows_resolver_wrapper(LPVOID lParam)
{
	return (DWORD)resolver_main(RESOLVERADDR);
}

#else

void *linux_bsd_resolver_wrapper(void *arg)
{
	return (void*)resolver_main(RESOLVERADDR);
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
  if (!locate_resolver(f, RESOLVERADDR))
	  return NULL;

#ifndef _MSC_VER
  // create and launch the resolver thread
  pthread_t *ret = new pthread_t;
  if (pthread_create(ret, NULL, linux_bsd_resolver_wrapper, NULL) != 0) {
	  eprintf( "There was an error creating the resolver thread\n");
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

/* Get the mandatory TAP options */
bool get_tap_options(ConfigFile &f, uint32_t &tapAddr, uint32_t &tapMask)
{
  bool bRet = true;
  const string *tempString = f.get("tapnetaddr");
  struct in_addr addr;
  memset(&addr, 0, sizeof(addr));

  /* Get the network */
  if (NULL != tempString)
  {
    if (!inet_pton(AF_INET, tempString->c_str(), &addr))
    {
      Eprintf( "Config File: tapnetaddr %s is not a valid IP address\n", tempString->c_str());
      bRet = false;
    }
    else if (0 == addr.s_addr)
    {
      Eprintf( "ConfigFile: tapnetaddr cannot be 0\n");
      bRet = false;
    }
    if (bRet)
    {
      tapAddr = ntohl(addr.s_addr);

      /* Get net mask */
      const string *tempString = f.get("tapnetmask"); // redeclaration
      if (NULL != tempString)
      {
        memset(&addr, 0, sizeof(addr));
        if (!inet_pton(AF_INET, tempString->c_str(), &addr))
        {
          Eprintf( "Config File: tapnetmask %s is not a valid net mask\n", tempString->c_str());
          bRet = false;
        }
        else if (0 == addr.s_addr)
        {
          Eprintf( "Config File: tapnetmask cannot be 0\n");
          bRet = false;
        }
        tapMask = ntohl(addr.s_addr);

        /* Check to see that the TUN/TAP network is a network address, and NOT a device address */
        if (tapAddr & ~tapMask)
        {
          Eprintf("Config File: You seem to have entered a incorrect network address for "
            "the TUN/TAP device. Please make sure you did not enter the ADDRESS of the device\n");
          bRet = false;
        }
      }
      else
      {
        Eprintf( "Config File: Found tapnetaddr but not tapnetmask\n");
        bRet = false;
      }
    }
  }
  else
  {
     Eprintf("Config File: option \"tapnetaddr\" missing!\n");
    bRet = false;
  }
  return bRet;
}

bool get_options(ConfigFile &f, bool &server, uint16_t &port, uint32_t &tapAddr, uint32_t &tapMask, char logFile[])
{
  bool bRet = false;
  /* Get the config file */
  const string *log_file = f.get("log");
  if (log_file == NULL)
  {
     Eprintf("No log file provided. Using stderr\n");
     strcpy(logFile, "stderr");
  }
  else
  {
     strcpy(logFile, log_file->c_str());
  }

  /* IP address is automatic. No more config file! */
#if 0
  const string *ip_str = f.get("ip");
  if (ip_str == NULL) {
    eprintf( "No IP address found in configuration file\n");
    return false;
  }

  struct in_addr ip;
  if (!inet_pton(AF_INET, ip_str->c_str(), &ip)) {
    eprintf( "Unable to parse %s as IP address\n", ip_str->c_str());
    return false;
  }
  ip_addr = ntohl(ip.s_addr);
#endif
  const string* server_str = f.get("server");
  if (server_str == NULL)
  {
    Eprintf("Config File: \"server = true/false\" missing!\n");
    bRet = false;
  }
  else
  {
    if (server_str->compare("true") == 0)
    {
      server = true;
      bRet = true;
    }
    else if (server_str->compare("false") == 0)
    {
      server = false;
      bRet = true;
    }
    else
    {
      Eprintf("Config File: unknown value for config file option \"server\" %s\n", server_str->c_str());
      bRet = false;
    }
  }

  if (bRet)
  {
    /* Get the port */
    const string *port_str = f.get("port");
    if (port_str == NULL) {
      Eprintf( "Config File: No \"port\" option found in configuration file\n");
      bRet = false;
    }
    int p = atoi(port_str->c_str());
    if (p < 0 || p > 65535) {
      Eprintf( "Config File: Port %s is not valid\n", port_str->c_str());
      bRet = false;
    }
    port = p;

    if (bRet)
    {
       /* The network and mask of the TUN/TAP device. Try and get both the mask and the address (optional)*/
       bRet = get_tap_options(f, tapAddr, tapMask);
    }
  }
  return bRet;
}

#ifdef _MSC_VER
DWORD WINAPI win_pcap_arp_handler_wrapper(LPVOID lParam)
{
  PARP.Start();
  return 0;
}
#else

void* linux_pcap_arp_handler_wrapper(void* lParam)
{
  PARP.Start();
  return 0;
}
#endif

void spawnPcapArpHandler()
{
#ifndef _MSC_VER
  // create and launch the resolver thread
  pthread_t *ret = new pthread_t;
  if (pthread_create(ret, NULL, linux_pcap_arp_handler_wrapper, NULL) != 0)
  {
	  eprintf( "There was an error creating the resolver thread\n");
	  delete ret;
	  ret = NULL;
  }
#else
   HANDLE ret = NULL;
   ret = CreateThread(
			NULL,                      // default security attributes
			0,                         // use default stack size 
			win_pcap_arp_handler_wrapper,  // thread function name
			NULL,                // argument to thread function 
			0,                         // use default creation flags 
			0);
#endif
}

#ifdef DEBUG
uint32_t TAPNET = 0x0001000A;
uint32_t TAPMASK = 0x80ffffff;
uint32_t NATADDR = 0x0101000A;
#endif


int main(int argc, char *argv[])
{

  /* Config file */
  ConfigFile f;
  string config_file = "/etc/nat3.conf";
  if (argc > 1)
  {
    config_file = argv[1];
  }
  if (!f.load(config_file))
  {
    Eprintf( "Error loading configuration file: %s\n", f.error());
    return 2;
  }
  uint32_t ip;
  uint16_t port;
  uint32_t tapNetmask, tapAddr;
  bool server;
  char logFile[256];
  if (!get_options(f, server, port, tapAddr, tapNetmask, logFile))
  {
    return 1;
  }

  open_log_file(logFile);

  /* Windows WSAStartup - before resolver or tun_mgr */
#ifdef _MSC_VER
  if (!getWindowsVersion())
  {
    eprintf("Couldnt get Windows version\n");
    return 3;
  }
  else if (!WSACleanup())
  {
    eprintf("Cleanup failed! %d\n", GetLastError());
  }

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
  {
    eprintf("win_tun_mgr: WSAStartup failed %d!\n", GetLastError());
  }
#endif /* _MSC_VER */
    
   printf("Welcome to NAT3D.\n");
  PARP.QueryAdapterDetails(ip);
  /* Server only: PCAP arp handler */
  if (server)
  {
    PARP.Init(tapAddr, tapNetmask);
    spawnPcapArpHandler();
  }
  /* Client only: Resolver */
  else
  {
    if (_spawnResolver(f) == NULL)
    {
      return 1;
    }
  }

  /* Tunnel manager */
  TunnelMgr &mgr = TunnelMgr::getInstance();
  mgr.init(ip,
    port,
    tapAddr,
    tapNetmask,
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
