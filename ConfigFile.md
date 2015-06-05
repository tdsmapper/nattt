# Introduction #

The NAT3D configuration file is required by NAT3D to know the following details:

  * DNS Resolver address
  * IP address of the interface on which to listen
  * Port number on which to listen
  * Subnet and mask for the TUN device
  * Is this instance a server or client?

The options are entered in the configuration file in the format below:

_option_ = _value_

## Sample config. file ##

```
server = false
log = none
port = 9876
resolver = a.b.c.d
tapnetaddr = 10.0.1.0
tapnetmask = 255.255.255.0
natbox = 10.0.1.0
```

In the NATTT client (_server = false_), note that the 10.0.1.0 subnet is assumed to be outside the local subnet. i.e. if your NAT subnet is 10.0.1.0, you need to use another free subnet here.
Note that if you do not provide an _ip_ option (shown below), you will be asked for which network interface you to use (See description of the option _ip_ below on guideline to choosing the right interface)

```
ip = 10.0.0.135
log = stderr
server = true 
port = 9876
resolver = a.b.c.d
tapnetaddr = 10.0.0.248
tapnetmask = 255.255.255.248
```

This config is for NAT3D  running on a host behind the NAT i.e. a PC/Mac. Therefore, the subnet assigned to the TUN device is an unused sub-subnet of the local subnet. i.e. in the config file above, the NAT subnet is something like 10.0.0.0/24.
However, if NAT3D were running on a NAT, it should use any subnet outside of the local subnet (The NAT is the default route for all addresses on that subnet).

# Explanation of options #

## DNS Resolver address (option: _resolver_) ##
The address of the DNS resolver is the address of the DNS database that contains details about the remote servers you want to reach.

To set up a resolver, see [instructions](ResolverSetup.md).

Example: resolver = 127.0.0.1

## IP address of the interface used for tunneling (option: _ip_) ##

For the NAT3D server, this is typically the interface connecting to the NAT i.e. Wifi or Ethernet.
For the NAT3D client, this is the interface that connects to the Internet. It can be the same as the interface connecting to the NAT depending on your configuration.

Example: _ip = a.b.c.d_

**Please do not enter 127.0.0.1 for the address of the interface.**

If you do not provide this option, you will be asked which interface to use. If you provide this option, NAT3D will use the interface with that IP address.

The command to get the ip address of the interfaces is _ifconfig_ on Linux/UNIX/Mac OS X. The interfaces are typically named "eth0/1.." for Ethernet and "wlan0/1.." or "en0/1.." on the Mac.

On Windows, finding your IP address typically involves right-clicking the network connection icon in the tray (near the date), choosing properties, and one of options from there (depending on your specific Windows OS).


## Port number on which to listen (option: _port_) ##

The port number is the port number on which NAT3D listens for incoming tunnel packets. Please note that you need to forward the port from the NAT box to the server installation of NAT3D for the application to work. For more details on how to forward the port, visit [Port Forward](http://www.portforward.com/).

Example: port = 100

## TUN/TAP details (mandatory) ##

If you plan to use NAT3D as a client, or as a server with the intention of making the server the only machine reachable behind the NAT box, you may omit these options

**TAP address and netmask (Options: _tapnetaddr_, _tapnetmask_**

The options _tapnetaddr_ and _tapnetmask_ describe the IP address of the TUN adapter/device and the address range the TAP device listens on.

## Logging (option: _log_) ##
This is the log file to which the NAT3D events are sent. NAT3D appends the log to this file. Assigning _log = stderr_ sends all event output to stderr. Assigning _log = none_ sends all output to /dev/null or the NULL device on Windows i.e. the user does see any output on the screen.



# <font color='red'> Deprecated </font> #

## Bridging (Optional, Option: _bridge_) ##

Setting _bridge_ to "on" means that no address is assigned to the TAP interface/adapter. Setting it to off means the TAP device/adapter is assigned the IP address specified.


## IP Address of the interface on which to listen (option: _ip_) ##

<font color='red'>Automated since <a href='https://code.google.com/p/nattt/source/detail?r=125'>Revision 125</a></font>

The IP address of the network interface on which to listen for incoming tunneled packets. If you have multiple interfaces, the meanings differ for both the client and the server.

**Client:**
Address of interface on which you expect incoming packets to arrive. For a common machine, you probably have 2 interfaces - an Ethernet and a Wireless-LAN. Enter the address of the interface which is connected to the Internet.

The command to get the ip address of the interfaces is _ifconfig_ on Linux/UNIX/Mac OS X. The interfaces are typically named "eth0/1.." for Ethernet and "wlan0/1.." or "en0/1.." on the Mac.

On Windows, finding your IP address typically involves right-clicking the network connection icon in the tray (near the date), choosing properties, and one of options from there (depending on your specific Windows OS).

_**Please do not enter 127.0.0.1 for the address of the interface.**_

Example: ip = 70.23.223.12