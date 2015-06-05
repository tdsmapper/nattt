# Introduction #

How to port NAT3D server daemon to a NAT box such as a wifi router. This also serves as an introduction on how to compile a simple program for the router.

# Install OpenWRT on the router #

You need to install some open source Linux firmware for NAT3D first. OpenWRT and DD-WRT are examples. Its easier to install all required libraries on OpenWRT.

  * To install OpenWRT, look http://wiki.openwrt.org/doc/howto/installing. You can download the correct firmware for OpenWRT from the site.
  * Some excellent instructions about installation of firmware is at the [here DD-WRT site](http://www.dd-wrt.com/wiki/index.php/Installation). This is generally applicable to all open source firmware for NATs. It is recommended to follow instructions from the DD-WRT site even if you want to install OpenWRT especially regarding how to reset the router, flash the router with the new firmware, and router-specific details that DD-WRT provides [here](http://www.dd-wrt.com/site/support/router-database)
  * Consider glancing through the [peacock thread](http://www.dd-wrt.com/phpBB2/viewtopic.php?t=51486). It is very useful.
  * DD-WRT has a NAT/router-specific page [here](http://www.dd-wrt.com/site/support/router-database). This contains specific details about your hardware i.e. the hardware capabilities - RAM, flash storage etc. It also contains some important router-specific details such as

# Install C++ library on the router #
Once you install OpenWRT/DD-WRT (its easier to install libraries on OpenWRT), you need to install a C++ library on the router since NAT3D is written in C++. You can install either uclibc++ (a mini-library) or libstdc++ (the standard C++ library; wont fit in the space available on many NATs). To do so, do the following in the router ssh terminal:

```
ipkg update
ipkg install uclibcxx
```
_uclibcxx_ above may also be _uclibc++_ depending on the version/make of your firmware.
_ipkg_ may be _opkg_ depending on your firmware version/make.

If this does not work, there might be some specific details http://wiki.openwrt.org/oldwiki/openwrtdocs/packages here].

# Install the TUN device on the router #
To install the TUN device, do the following:

```
ipkg update
ipkg install kmod-tun
```
_ipkg_ may be _opkg_ depending on your firmware version/make.

You may need to create the TUN device file i.e. the UNIX filesystem interface to the TUN device (/dev/net/tun). If it does not exist at that location, create it as follows:

```
mkdir /dev/net
mknod /dev/net/tun c 10 200  (Linux kernel 2.4.x)
```

# Set firewall rules on router #

Some router/NAT to allow traffic to/from TUN device firewall rules needed to be changed as below. br0 below is the interface to the private network.

```
### Allow NAT3D traffic on tun* devices
iptables -A forwarding_rule -i tun+ -o br0 -j ACCEPT
iptables -A forwarding_rule -i br0 -o tun+ -j ACCEPT
iptables -A input_rule -i tun+ -j ACCEPT
iptables -A output_rule -o tun -j ACCEPT
```

# Build NAT3D server daemon for the NAT #

This also serves as an introduction on how to compile a simple program for the router. Just change the options as below in the program's Makefile.

  * Download the build system/OpenWRT SDK from [here](http://wiki.openwrt.org/oldwiki/buildingpackageshowto) or [here](http://downloads.openwrt.org/whiterussian/newest/). You do not require the image builder which is for building your own firmware.
  * Install the c++ library for the build system using via a feed using _/scripts/feeds_.
  * Below is a sample NAT3D makefile for OpenWRT. Edit the NAT3D makefile to remove the pcap\_arp\_handler, resolver and all DNS files (not required on NAT3D). Only the Tunnel manager and related files is required for the server daemon.
  * In the NAT3D Makefile, set the compiler option (i.e. the CXX option) to the compiler in the package (typically located at _staging\_dir/toolchain-mipsel\_gcc3.4.6/bin_). You need to use the mipsel-linux-uclibc-g++ compiler.
  * Add the -nodefaultlibs and -nostdinc++ options to make sure that NAT3D is not compiled against the C++ libraries on the machine.
  * Also edit the NAT3D Makefile to link with the uclibc++ library located located within the build system by using a -L option in CFLAGS. Also use the -I option in CFLAGS to tell the Makefile where the location of the uclibc++ include directory.
  * Make NAT3D. It will be compiled as a binary for the firmware. You can now run NAT3D as with any application (i.e. _./nat3d_)
  * It is also possible to make a NAT3D ipkg/opkg and install the ipkg on the router.

A sample makefile follows:
```
CC =    gcc 
CXX = (build system location)/OpenWrt-SDK-brcm-2.4-for-Linux-i686/staging_dir/toolchain-mipsel_gcc3.4.6/bin/mipsel-linux-g++
CFLAGS = -nostdinc++ -nodefaultlibs
CFLAGS += -DHAVE_CONFIG_H -D_TUN_MGR_DEBUG
CFLAGS += -O2 -L(build system location)/OpenWrt-SDK-brcm-2.4-for-Linux-i686/staging_dir/mipsel/usr/lib
CFLAGS += -I(build system location)/OpenWrt-SDK-brcm-2.4-for-Linux-i686/staging_dir/mipsel/usr/include/uClibc++
CFLAGS += -I(build system location)/OpenWrt-SDK-brcm-2.4-for-Linux-i686/staging_dir/toolchain-mipsel_gcc3.4.6/include
CFLAGS += -L(build system location)/OpenWrt-SDK-brcm-2.4-for-Linux-i686/staging_dir/toolchain-mipsel_gcc3.4.6/lib
CFLAGS += -D_REENTRANT
CFLAGS += -DDEBUG

LDFLAGS = -luClibc++ -luClibc -lgcc
DEFINES = -D_POSIX_THREADS -DHAVE_CONFIG_H
OBJS = tun_mgr.o tun_device.o tun_queue.o tun_in_ent.o tun_out_ent.o tun_ent.o mutex_helper.o config_file.o functions.o linux_tun_mgr.o log.o 

PROG = nat3d nat3ping


CXXFLAGS += $(CFLAGS)

.cc.o:
   $(CXX) $(CXXFLAGS) $(DEFINES) -c $< $(LDFLAGS)

all: $(PROG)

$(PROG): $(OBJS)
   $(CXX) $(CXXFLAGS) $(DEFINES)  -o ../bin/$@ $@.cc $(OBJS) $(LDFLAGS)


clean:
   rm -f $(PROG) $(OBJS)                      
```