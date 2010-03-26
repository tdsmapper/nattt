#include <stdio.h>
#include "pcap_arp_handler.h"
#include "pcap.h"
#include "functions.h"
#include "types.h"
#include <string.h>

#ifndef _MSC_VER 
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#endif

pcap_t           * ADAPTERHANDLE; //Global for use in callback
unsigned char MACADDR[MACADDRSIZE];
uint32_t INTERFACEIP;

/* Take the adapter name, adapter address, host address and set a filter that retrieves
all ARP queries for the network on the TAP device, except from the local host, since that
is handled by the TUN/TAP driver */
bool PcapArpHandler::setPcapFilter()
{  
  bool bRet = true;
  //Sample expresion: "arp dst net 10.0.0.252 mask 255.255.255.252 and not arp src host 10.0.0.7 and ...";
  char szFilterExp[256] = "arp dst net ";

  // Append the net
  struct in_addr inIpAddr;
  inIpAddr.s_addr = htonl(m_uTuntapNet);
  char *pszNet = inet_ntoa(inIpAddr);
  strcat(szFilterExp, pszNet);

  // Append mask
  strcat(szFilterExp, " mask ");
  inIpAddr.s_addr = htonl(m_uTuntapMask);
  char *pszMask = inet_ntoa(inIpAddr);
  strcat(szFilterExp, pszMask);

  // Append the host address. This would be handled by the TUN/TAP driver itself.
  strcat(szFilterExp, " and not arp src host ");
  inIpAddr.s_addr = htonl(m_uInterfaceIP);
  char *pszHostIP = inet_ntoa(inIpAddr);
  strcat(szFilterExp, pszHostIP);

  // Handle ARP for everyone except the NAT box/router (assumed to be Net Addreess + 1. i.e. 10.0.0.1)
  // Check if the NAT box is on the same network as TUN/TAP device.
  // Then in that case, ignore the ARP request for the NAT box alone.
  if ((m_uNatAddr & m_uTuntapNet) == m_uTuntapNet)
  {
    inIpAddr.s_addr = m_uNatAddr;
    char *pszNatIP = inet_ntoa(inIpAddr);
    strcat(szFilterExp, " and not arp dst host ");
    strcat(szFilterExp, pszNatIP);
  }

  eprintf("The filter applied is %s\n", szFilterExp);

  struct bpf_program fp;
  if (pcap_compile(ADAPTERHANDLE, &fp, szFilterExp, 0, m_uTuntapNet) == -1)
  {
    eprintf("Couldn't parse filter %s: %s\n", szFilterExp, pcap_geterr(ADAPTERHANDLE));
    bRet = false;
  }
  if (pcap_setfilter(ADAPTERHANDLE, &fp) == -1)
  {
    eprintf("Couldn't install filter %s: %s\n", szFilterExp, pcap_geterr(ADAPTERHANDLE));
    bRet = false;
  }
  return bRet;
}

/* Show a list of adapters to the user, ask him which one to listen on for both the ARP replying,
and as well as for the address on which to listen for incoming Tunneled packets */
bool PcapArpHandler::QueryAdapterDetails(uint32_t &ip)
{
  bool bRet = false;
  pcap_if_t           * allAdapters;
  pcap_if_t           * adapter;
  char                  errorBuffer[PCAP_ERRBUF_SIZE];

  // retrieve the adapters from the computer
  if (pcap_findalldevs(&allAdapters, errorBuffer) == -1)
  {
    fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);
    bRet = false;
  }
  else if(allAdapters == NULL)
  {
    printf("\nNo adapters found! Make sure WinPcap is installed.\n");
    bRet = false;
  }
  else
  {
    // print the list of adapters along with basic information about an adapter
    int crtAdapter = 0;
    for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)
    {
      printf("\n%d.%s ", ++crtAdapter, adapter->name);
      printf("-- %s\n", adapter->description);
    }
    printf("\n" );
    printf("Enter the adapter number between 1 and %d:", crtAdapter );
    int adapterNumber;
    scanf("%d", &adapterNumber);
    if ((adapterNumber < 1) || (adapterNumber > crtAdapter))
    {
      printf("\nAdapter number out of range.\n");
      pcap_freealldevs(allAdapters);
      bRet = false;
    }
    else
    {
      /* parse the list until we reach the desired adapter */
      adapter = allAdapters;
      for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)
      {
        adapter = adapter->next;
      }

      /* TODO: For now, find *any* AF_INET address. */
      pcap_addr* adapterAddress = adapter->addresses;
      while (NULL != adapterAddress)
      {
        if (AF_INET == adapterAddress->addr->sa_family)
        {
          struct sockaddr_in *sin =  (struct sockaddr_in*)adapterAddress->addr;
          INTERFACEIP = m_uInterfaceIP = ntohl(sin->sin_addr.s_addr);
          ip = m_uInterfaceIP;
          break;
        }
        adapterAddress = adapterAddress->next;
      }

      /* Adapter name and MAC address */
      strcpy(m_szAdapterName, adapter->name);
      bRet = GetInterfaceMacAddress(m_szAdapterName, MACADDR);
      if (!bRet)
      {
        eprintf("Could not retrieve MAC address!\n");
      }
    }
    pcap_freealldevs(allAdapters);
  }
  return bRet;
}

/* Takes the network of the TUN/TAP device, not the address of the TUN/TAP device */
bool PcapArpHandler::Init(uint32_t &p_uTuntapNet, uint32_t &p_uTuntapMask,  uint32_t &p_uNatAddr)
{
  bool bRet = false;
  m_uTuntapNet = p_uTuntapNet;
  m_uTuntapMask = p_uTuntapMask;
  m_uNatAddr = m_uNatAddr;
  char errorBuffer[PCAP_ERRBUF_SIZE];
  if ((ADAPTERHANDLE = pcap_open_live(m_szAdapterName, ADAPTERBUFSIZE, 1, -1, errorBuffer)) == NULL)
  {
    eprintf("Unable to open the adapter %s\n", m_szAdapterName);
  }
  else if(!setPcapFilter())
  {
    eprintf("Unable to set up pcap filter!\n");
  }
  else
  {
    eprintf("Started adapter capture on %s\n", m_szAdapterName);
    bRet = true;
  }
  return bRet;
}

void PcapArpHandler::Start()
{
  pcap_loop(ADAPTERHANDLE, -1, pcap_arp_callback, NULL);
}

void pcap_arp_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* inPacket)
{
  fprintf(stderr, "Read a packet of size %d\n", pkthdr->len);

  int outPacketSize = sizeof(struct ether_header) + sizeof(struct arphdr) + sizeof(struct arp);
  u_char* outPacket = new u_char[outPacketSize];
  struct ether_header* outEthHeader = (struct ether_header*) outPacket;
  struct arphdr *outArpHeader       = (struct arphdr*) &outPacket[sizeof(struct ether_header)];
  struct arp *outArp                = (struct arp*) &outPacket[sizeof(struct ether_header) + sizeof(arphdr)];

  struct ether_header* inEthHeader = (struct ether_header*)inPacket;
  struct arp *inArp                = (struct arp*) &inPacket[sizeof(struct ether_header) + sizeof(arphdr)];

  /* Set up the Ethernet header */
  memcpy(outEthHeader->ether_dhost, inEthHeader->ether_shost, MACADDRSIZE);
  memcpy(outEthHeader->ether_shost, MACADDR, MACADDRSIZE);
  outEthHeader->ether_type =htons(ETHERTYPE_ARP);

  /* Set up the ARP header */
  outArpHeader->ar_hln = MACADDRSIZE;
  outArpHeader->ar_op = htons(ARPOP_REPLY);
  outArpHeader->ar_pln = IPADDRSIZE;
  outArpHeader->ar_pro = htons(ETHERTYPE_IP);
  outArpHeader->ar_hrd = htons(TYPE_ETHERNET);

  /* Set up ARP body */
  memcpy(outArp->SHA, MACADDR, MACADDRSIZE);
  memcpy(outArp->THA, inArp->SHA, MACADDRSIZE);
  outArp->SPA = inArp->TPA;
  outArp->TPA = inArp->SPA;

  if(pcap_sendpacket(ADAPTERHANDLE, outPacket, outPacketSize) != 0)
  {
    eprintf("Error sending the packet: %s \n", pcap_geterr(ADAPTERHANDLE));
    exit(-1);
  }
  delete[] outPacket;
}
