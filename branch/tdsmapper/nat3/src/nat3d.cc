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
#include "resolver.h"
#include "tun_mgr.h"
#include "config_file.h"
//#include "types.h"
#include "functions.h"

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
	uint32_t *pIp = (uint32_t*)lParam;
	uint32_t ip = *pIp;
	return (DWORD)resolver_main(ip);
}

#else

void *linux_bsd_resolver_wrapper(void *arg)
{
	uint32_t *ip = (uint32_t *)arg;
	return (void*)resolver_main(*ip);
}

#endif


void* _spawnResolver(ConfigFile &f) //changed from pthread_t
{
  uint32_t ip;
  if (!locate_resolver(f, ip))
	  return NULL;

#ifndef _MSC_VER
  // create and launch the resolver thread
  pthread_t *ret = new pthread_t;
  if (pthread_create(ret, NULL, linux_bsd_resolver_wrapper, (void *)&ip) != 0) {
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
			(LPVOID)&ip,               // argument to thread function 
			0,                         // use default creation flags 
			0);
#endif


  return ret;
}


bool get_options(ConfigFile &f, uint32_t &ip_addr, uint16_t &port) {
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
    return false;
  }
    
  uint32_t ip;
  uint16_t port;
  if (!get_options(f, ip, port))
    return 1;
  if (_spawnResolver(f) == NULL)
    return 1;



  TunnelMgr &mgr = TunnelMgr::getInstance();
  mgr.init(ip, port);
  mgr.listen();

  return 0;
}
