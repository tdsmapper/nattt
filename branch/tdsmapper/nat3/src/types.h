/* types.h: Type portability between Windows and Linux/BSD */
#ifndef __TYPES_H__
#define __TYPES_H__

#ifdef _TUN_MGR_DEBUG
#define dprintf eprintf
#else
#define dprintf(...) do { } while(0)
#endif

#define eprintf(X, ...) fprintf(stderr, __FILE__ " [%d] - "  X, __LINE__, ##__VA_ARGS__)

#ifdef _MSC_VER
  #include <Winsock2.h>
  #include <Windows.h>
#else
   #include <stdlib.h>
   #include <stdint.h>
#endif

/*
 * OS Dependent types
 */
/* Integer types */

#ifdef _MSC_VER // Visual Studio/Microsoft equivalents of UNIX datatypes
	typedef unsigned __int8 byte;
	typedef unsigned __int8 uint8_t;
	typedef unsigned __int16 uint16_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef signed __int8 int8_t;
	typedef signed __int16 int16_t;
	typedef signed __int32 int32_t;
	typedef signed __int64 int64_t;
#endif


/*
 * OS Independent types
 */

/* Generic types */
typedef unsigned char u_char;
typedef unsigned short int u_short;  // TODO: Check this type works well

/* Networking types */
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_CRC_SIZE    4
#define ETHERNET_READ_SIZE (m_iTunMTU + ETHERNET_HEADER_SIZE + ETHERNET_CRC_SIZE)
#define LISTEN_READ_SIZE   (IP_MAXPACKET)

/*
 *  OS Dependent types
 */
/* *NIX  */
#ifndef _MSC_VER 
	typedef int HANDLE;
	typedef int SOCKET;
   typedef ssize_t SSIZE_T;

/* Windows */
#else
  typedef int socklen_t;
  /*
  * All the network headers
  */
  /* IP header version 4 as per RFC 791 */
  #define    IP_MAXPACKET    65535           /* maximum packet size */

  #pragma pack(1)
  struct ip
    {
      unsigned char ip_hl:4;     /* header length */
      unsigned char ip_v:4;      /* version */
      uint8_t ip_tos;       /* type of service */
      u_short ip_len;        /* total length */
      u_short ip_id;         /* identification */
      u_short ip_off;        /* fragment offset field */
  #define  IP_RF 0x8000         /* reserved fragment flag */
  #define  IP_DF 0x4000         /* dont fragment flag */
  #define  IP_MF 0x2000         /* more fragments flag */
  #define  IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
      uint8_t ip_ttl;       /* time to live */
      uint8_t ip_p;         /* protocol */
      u_short ip_sum;        /* checksum */
      struct in_addr ip_src, ip_dst;  /* source and dest address */
    };


  /* Ehternet header */
  #define ETH_ADDR_LEN      6           /* Ethernet address length */
  #define ETHERTYPE_IP      0x0800      /* IP */
  #define ETHERTYPE_ARP     0x0806      /* Address resolution */

#pragma pack(1)
  struct ether_header
  {
    uint8_t  ether_dhost[ETH_ADDR_LEN];  /* destination eth addr */
    uint8_t  ether_shost[ETH_ADDR_LEN];  /* source ether addr */
    uint16_t ether_type;                 /* packet type ID field  */
  };

  /* ARP Header */
  #define ARPHRD_ETHER    1     /* Ethernet 10/100Mbps.  */
  #define ARPOP_REPLY     2     /* ARP reply.  */
  #define ARPOP_REQUEST  1      /* ARP request.  */
  #define ARPOP_RREPLY   4      /* RARP reply.  */
  #define ARPOP_RREQUEST  3     /* RARP request.  */

#pragma pack(1)
  struct arphdr
  {
    unsigned short int ar_hrd;      /* Format of hardware address.  */
    unsigned short int ar_pro;      /* Format of protocol address.  */
    unsigned char ar_hln;           /* Length of hardware address.  */
    unsigned char ar_pln;           /* Length of protocol address.  */
    unsigned short int ar_op;       /* ARP opcode (command).  */
  };

  /* ICMP Headers */
  #define ICMP_ECHOREPLY     0  /* Echo Reply        */
  #define ICMP_DEST_UNREACH  3  /* Destination Unreachable */
  #define ICMP_SOURCE_QUENCH 4  /* Source Quench     */
  #define ICMP_REDIRECT      5  /* Redirect (change route) */
  #define ICMP_ECHO    8  /* Echo Request         */
  #define ICMP_TIME_EXCEEDED 11 /* Time Exceeded     */
  #define ICMP_PARAMETERPROB 12 /* Parameter Problem    */
  #define ICMP_TIMESTAMP     13 /* Timestamp Request    */
  #define ICMP_TIMESTAMPREPLY   14 /* Timestamp Reply      */
  #define ICMP_INFO_REQUEST  15 /* Information Request     */
  #define ICMP_INFO_REPLY    16 /* Information Reply    */
  #define ICMP_ADDRESS    17 /* Address Mask Request    */
  #define ICMP_ADDRESSREPLY  18 /* Address Mask Reply      */
  #define NR_ICMP_TYPES      18

  /* ICMP RA Header */
  /*
   * Internal of an ICMP Router Advertisement
   */
  struct icmp_ra_addr
  {
    uint32_t ira_addr;
    uint32_t ira_preference;
  };


  /* ICMP Header */
  struct icmp
  {
  uint8_t  icmp_type;  /* type of message, see below */
  uint8_t  icmp_code;  /* type sub code */
  uint16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;     /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr; /* gateway address */
    struct ih_idseq     /* echo datagram */
    {
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;
    uint32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      uint16_t ipm_void;
      uint16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      uint8_t irt_num_addrs;
      uint8_t irt_wpa;
      uint16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
  #define  icmp_pptr   icmp_hun.ih_pptr
  #define  icmp_gwaddr icmp_hun.ih_gwaddr
  #define  icmp_id     icmp_hun.ih_idseq.icd_id
  #define  icmp_seq icmp_hun.ih_idseq.icd_seq
  #define  icmp_void   icmp_hun.ih_void
  #define  icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
  #define  icmp_nextmtu   icmp_hun.ih_pmtu.ipm_nextmtu
  #define  icmp_num_addrs icmp_hun.ih_rtradv.irt_num_addrs
  #define  icmp_wpa icmp_hun.ih_rtradv.irt_wpa
  #define  icmp_lifetime  icmp_hun.ih_rtradv.irt_lifetime
  union
  {
  struct
      {
        uint32_t its_otime;
        uint32_t its_rtime;
        uint32_t its_ttime;
      } id_ts;
      struct
      {
        struct ip idi_ip;
        /* options and then 64 bits of data */
      } id_ip;
      struct icmp_ra_addr id_radv;
      uint32_t   id_mask;
      uint8_t    id_data[1];
    } icmp_dun;
  #define  icmp_otime  icmp_dun.id_ts.its_otime
  #define  icmp_rtime  icmp_dun.id_ts.its_rtime
  #define  icmp_ttime  icmp_dun.id_ts.its_ttime
  #define  icmp_ip     icmp_dun.id_ip.idi_ip
  #define  icmp_radv   icmp_dun.id_radv
  #define  icmp_mask   icmp_dun.id_mask
  #define  icmp_data   icmp_dun.id_data
  };


/* UDP Header */
  struct udphdr
  {
    uint16_t uh_sport;   /* source port */
    uint16_t uh_dport;   /* destination port */
    uint16_t uh_ulen;    /* udp length */
    uint16_t uh_sum;     /* udp checksum */
  };



#endif /* _MSC_VER */
  



#endif /* __TYPES_H__ */
