# Introduction #

Installation on Windows requires 2 major steps:
  1. Installation of TUN/TAP driver from OpenVPN
  1. Disabling the firewall from blocking traffic on the TUN/TAP Device

All libraries/drivers below are found in the SVN repository under _/branch/tdsmapper/nat3\_libs_. Use this in case the drivers/libs are no longer available.

# Installation of the TUN/TAP driver from OpenVPN #

As of now, the easiest way to get this done is by downloading the [OpenVPN](http://openvpn.net/index.php/open-source/downloads.html) Windows Installer (1 MB in size).

Once you have downloaded the OpenVPN Windows installer, open it, and install only the TAP-WIN32 driver from the "Choose Components" screen.

![http://img208.imageshack.us/img208/6015/openvpntaponly.png](http://img208.imageshack.us/img208/6015/openvpntaponly.png)

# Disabling the firewall on the TUN/TAP device #

One issue you may encounter with using NAT3D is that the Windows Firewall or a firewall from any other provider may not trust the network traffic on the TUN/TAP. This can lead to incorrect functioning of NAT3D.

Therefore, you might have to add the TUN/TAP device's network as a safe/accepted/trusted network. The default network used by the TUN/TAP device is 10.254.0.1/16

# Official site #
If none of the above are helpful, please visit the [official site](http://openvpn.net/INSTALL-win32.html).

# Install WinPCAP #
Install the pcap library from [here](http://www.winpcap.org/). You may also find it in the SVN repository.