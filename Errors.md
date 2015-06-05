## List of errors faced with NATTT: ##

### Unknown Ethertype FE0A ###
The problem is that NAT3 Daemon expects to open a TAP device, but opened
a TUN device instead. Add the following
to the makefile CFLAGS: -DNAT3`_`TAP.

### NXDOMAIN not returned by BIND9 on "A" Query ###
In several documents associated with the NATTTT Daemon, it is mentioned that the
application expects NXDOMAINs (Non-Existant Domains) to be returned by
BIND9 when the user application attempts to do a DNS query, at which point
the NAT3 Daemon takes over and re-issues the query with the custom DNS
Record type 1.

However, The NAT3 daemon checks for either a NXDOMAIN or for an empty answer section in the reply to the query.

### BIND9 complains about unknown RR type with the custom RR type ###
This was an issue that came up with a version of BIND9 unexpectedly. The
solution followed at that time was to upgrade the version of BIND9 to the latest
version.

### Packet sent from NAT3D to machine X on network, but no reply ###
Check that NAT3D is handling ARP reply to machine X i.e. sending an ARP reply using wireshark/tcpdump etc. Also using wireshark/tcpdump, make sure the packet arriving on X has the correct checksum.


### Bridge mysteriously changes address every time NAT3D Runs/quits ###
<font color='red'>(Deprecated: No longer in use)</font>
Windows: You probably have set the TUN/TAP device media status to "Application Controlled", which means that every time you start the TUN/TAP device, the bridge requests a new IP address.
Back to [introduction](Introduction.md).

### The TUN/TAP interface is not persistent ###
Linux/Mac: Look at tunctl
Windows: Go to the Networking center/Networking and devices. Click on the TUN/TAP device, click properties, click configuration and set the "Media Status" parameter to "Always connected"