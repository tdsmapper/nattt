# Introduction #

  * Windows uses the TUN/TAP driver from OpenVPN. Instructions to download and install are [here](WindowsInstallation.md).
  * <font color='red'> Bridging abandoned. NAT3D uses routing instead </font>. The driver is used in the TAP mode mainly to support ethernet-TAP [bridging](http://openvpn.net/bridge.html).
  * 

# Specific notes w.r.t Network behavior of the TAP device #
  * <font color='red'> Bridging abandoned. NAT3D uses routing instead. Notes about TAP device are presented for any future attempt at reviving bridging </font>.
  * You must handle ARP for the network device.
  * Replying to a query for an ARP request that asks for the address on the TUN/TAP device results in windows auto-configuring that device. See the source code for further details.
  * ARP queries for any network address in the TAP network should be replied with a different MAC address from that of the adapter (unlike Linux). See the source code for further details.


# References #
  * http://www.varsanofiev.com/inside/using_tuntap_under_windows.htm
  * http://ww.h7.dion.ne.jp/~qemu-win/TapWin32-en.html
  * http://openvpn.net/INSTALL-win32.html
  * http://colinux.wikia.com/wiki/TAP-Win32_Adapter_V8_%28coLinux%29
  * http://vtun.sourceforge.net/tun/faq.html