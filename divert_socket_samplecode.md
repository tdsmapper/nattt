From: http://www.faqs.org/docs/Linux-mini/Divert-Sockets-mini-HOWTO.html

Example program

Here is an example program that reads packets from a divert socket, displays them and then reinjects them back. It requires that the divert port is specified on the command line.
```
    #include <stdio.h>
    #include <errno.h>
    #include <limits.h>
    #include <string.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <getopt.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <signal.h>

    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <net/if.h>
    #include <sys/param.h>

    #include <linux/types.h>
    #include <linux/icmp.h>
    #include <linux/ip_fw.h>

    #define IPPROTO_DIVERT 254
    #define BUFSIZE 65535

    char *progname;

    #ifdef FIREWALL

    char *fw_policy="DIVERT";
    char *fw_chain="output";
    struct ip_fw fw;
    struct ip_fwuser ipfu;
    struct ip_fwchange ipfc;
    int fw_sock;

    /* remove the firewall rule when exit */
    void intHandler (int signo) {

      if (setsockopt(fw_sock, IPPROTO_IP, IP_FW_DELETE, &ipfc, sizeof(ipfc))==-1) {
        fprintf(stderr, "%s: could not remove rule: %s\n", progname, strerror(errno));
        exit(2);
      }

      close(fw_sock);
      exit(0);
    }

    #endif

    int main(int argc, char** argv) {
      int fd, rawfd, fdfw, ret, n;
      int on=1;
      struct sockaddr_in bindPort, sin;
      int sinlen;
      struct iphdr *hdr;
      unsigned char packet[BUFSIZE];
      struct in_addr addr;
      int i, direction;
      struct ip_mreq mreq;

      if (argc!=2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(1); 
      }
      progname=argv[0];

      fprintf(stderr,"%s:Creating a socket\n",argv[0]);
      /* open a divert socket */
      fd=socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);

      if (fd==-1) {
        fprintf(stderr,"%s:We could not open a divert socket\n",argv[0]);
        exit(1);
      }

      bindPort.sin_family=AF_INET;
      bindPort.sin_port=htons(atol(argv[1]));
      bindPort.sin_addr.s_addr=0;

      fprintf(stderr,"%s:Binding a socket\n",argv[0]);
      ret=bind(fd, &bindPort, sizeof(struct sockaddr_in));

      if (ret!=0) {
        close(fd);
        fprintf(stderr, "%s: Error bind(): %s",argv[0],strerror(ret));
        exit(2);
      }
    #ifdef FIREWALL
      /* fill in the rule first */
      bzero(&fw, sizeof (struct ip_fw));
      fw.fw_proto=1; /* ICMP */
      fw.fw_redirpt=htons(bindPort.sin_port);
      fw.fw_spts[1]=0xffff;
      fw.fw_dpts[1]=0xffff;
      fw.fw_outputsize=0xffff;

      /* fill in the fwuser structure */
      ipfu.ipfw=fw;
      memcpy(ipfu.label, fw_policy, strlen(fw_policy));

      /* fill in the fwchange structure */
      ipfc.fwc_rule=ipfu;
      memcpy(ipfc.fwc_label, fw_chain, strlen(fw_chain));

      /* open a socket */
      if ((fw_sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW))==-1) {
        fprintf(stderr, "%s: could not create a raw socket: %s\n", argv[0], strerror(errno));
        exit(2);
      }

      /* write a rule into it */
      if (setsockopt(fw_sock, IPPROTO_IP, IP_FW_APPEND, &ipfc, sizeof(ipfc))==-1) {
        fprintf(stderr, "%s could not set rule: %s\n", argv[0], strerror(errno));
        exit(2);
      }
     
      /* install signal handler to delete the rule */
      signal(SIGINT, intHandler);
    #endif /* FIREWALL */
      
      printf("%s: Waiting for data...\n",argv[0]);
      /* read data in */
      sinlen=sizeof(struct sockaddr_in);
      while(1) {
        n=recvfrom(fd, packet, BUFSIZE, 0, &sin, &sinlen);
        hdr=(struct iphdr*)packet;
        
        printf("%s: The packet looks like this:\n",argv[0]);
            for( i=0; i<40; i++) {
                    printf("%02x ", (int)*(packet+i));
                    if (!((i+1)%16)) printf("\n");
            };
        printf("\n"); 

        addr.s_addr=hdr->saddr;
        printf("%s: Source address: %s\n",argv[0], inet_ntoa(addr));
        addr.s_addr=hdr->daddr;
        printf("%s: Destination address: %s\n", argv[0], inet_ntoa(addr));
        printf("%s: Receiving IF address: %s\n", argv[0], inet_ntoa(sin.sin_addr));
        printf("%s: Protocol number: %i\n", argv[0], hdr->protocol);

        /* reinjection */

    #ifdef MULTICAST 
       if (IN_MULTICAST((ntohl(hdr->daddr)))) {
            printf("%s: Multicast address!\n", argv[0]);
            addr.s_addr = hdr->saddr;
            errno = 0;
            if (sin.sin_addr.s_addr == 0)
                printf("%s: set_interface returns %i with errno =%i\n", argv[0], setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)), errno);
        }
    #endif

    #ifdef REINJECT
       printf("%s Reinjecting DIVERT %i bytes\n", argv[0], n);
       n=sendto(fd, packet, n ,0, &sin, sinlen);
       printf("%s: %i bytes reinjected.\n", argv[0], n); 

       if (n<=0) 
         printf("%s: Oops: errno = %i\n", argv[0], errno);
       if (errno == EBADRQC)
         printf("errno == EBADRQC\n");
       if (errno == ENETUNREACH)
         printf("errno == ENETUNREACH\n");
    #endif
      }
    }
```
You can simply cut-n-paste the code and compile it with your favorite compiler. If you want to enable reinjection - compile it with the -DREINJECT flag, otherwise it will only do the interception.

In order to get it to work, compile the kernel and ipchains-1.3.8 as described above. Insert a rule into any of the firewall chains: input, output or forward, then send the packets that would match the rule and watch them as they fly through the screen - your interceptor program will display them and then reinject them back, if appropriately compiled.

For example:
```
    ipchains -A output -p TCP -s 172.16.128.10 -j DIVERT 4321
    interceptor 4321
```

will divert and display all TCP packets originating on host 172.16.128.10 (for instance if your host is a gateway). It will intercept them on the output just before they go on the wire.

If you did not compile the pass through option into the kernel, then inserting the rule effectively will create a DENY rule in the firewall for the packets you specified until you start the interceptor program. See more on that above

If you want to set a firewall rule through your program, compile it with -DFIREWALL option and it will divert all ICMP packets from the output chain. It will also remove the DIVERT rule from the firewall when you use Ctrl-C to exit the program. In this case using pass-through vs. non-pass-through divert sockets makes virtually no difference.