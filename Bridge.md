# <font color='red'> Deprecated. </font> #
<font color='red'> Document no longer in use. Provided so that future attempts to revive bridging. </font>
NAT3D can be built for bridging mode by using the NAT3\_TAP option. Please be aware that bridging does not work well with wireless interfaces. Since bridging was abandoned in Feb-March 2010, code written since then may break bridging code which was functional before Feb-March.

# Introduction #

Setting up a network bridge allows you to run several machines behind a NAT box, run NAT3D on only one machine, and allow connectivity to all the machines behind the NAT box.

![http://img651.imageshack.us/img651/2640/slide3i.jpg](http://img651.imageshack.us/img651/2640/slide3i.jpg)

As shown in the image, you need to bridge the TAP interface with the internet adapter (wireless or Ethernet interface).

Doing so allows network traffic on one interface to be seen by both the TAP device and the Internet adapter. Please note that once you have bridged two interfaces, both lose their IP addresses, and the "virtual bridge adapter" gets the IP address (DHCP or static) instead. Refer the [technical details page](BridgeTech.md) for more detailed information on how NAT3D uses the bridge.

Note that you might need to disable the firewall on the TAP interface (add as accepted network) for NAT3D to work.

# Windows #

Bridging on Windows is simple. Refer the end of this section on further instructions.

Windows Vista/7 users need to select "Adapter Settings" on the Network and Devices center page instead of following steps 1 & 2 as shown in the link at the end of this section.

![http://img186.imageshack.us/img186/7469/vistabridge.png](http://img186.imageshack.us/img186/7469/vistabridge.png)

Instructions on setting up a bridge are found [here](http://www.home-network-help.com/network-bridge.html).

# Linux #

Linux bridging is a well known concept used in sever other areas such as Virtualization.

Good information is found [here](http://www.linuxfoundation.org/collaborate/workgroups/networking/bridge#Creating_a_bridge_device). You just need to create and add devices to the bridge.