# <font color='red'> Deprecated. </font> #
<font color='red'> Document no longer in use. Provided so that future attempts to revive bridging. </font>
NAT3D can be built for bridging mode by using the NAT3\_TAP option. Please be aware that bridging does not work well with wireless interfaces. Since bridging was abandoned in Feb-March 2010, code written since then may break bridging code which was functional before Feb-March.

# Introduction #

A software network bridge is a layer 2 link between two network adapters. Therefore, all traffic on either interface is seen by both interfaces.

NAT3D works by assigning a new IP address from the subnet assigned in the [config file](ConfigFile.md). NAT3D responds with an ARP request for an address in the subnet it is assigned. Since the TAP interface and the Internet adapter are bridged, the TAP interface sees all traffic and NAT3D just picks up the traffic destined to its subnet.

The main loop of NAT3D listens to traffic on the Internet port (defined in [config file](ConfigFile.md)), as well as the TAP device. The daemon does is read from one and write into the other.

Therefore, if an external source sent a packet destined to another host via NAT3D, the following happens:

The packet is received on the Internet port of NAT3D. NAT3D converts the packet into a frame destined to the IP address specified in the packet. On Windows, NAT3D makes ARP requests. On Linux, this is automatic. Then, the packet is written out to the TAP device, and since the Internet interface and the TAP device are bridged, the packet reaches the host! This is best illustrated by a simple diagram:

![http://img202.imageshack.us/img202/7474/natbridge.png](http://img202.imageshack.us/img202/7474/natbridge.png)