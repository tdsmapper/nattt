# Introduction #

You need to be an administrator to run NATTT. However, in Linux/Mac, it is sufficient to have access to the TUN/TAP device.
Running NAT3D is with the following command on Linux/UNIX:

_./nat3d <config file>_
(Read about the [config file](ConfigFile.md)).

On Windows:
_NAT3win.exe <config file>_

# Server/Client #

The same application can function as both the server and the client. You need to change the [config file](ConfigFile.md) accordingly. When run as server, it is also required to forward the port from the NAT box to the port that NAT3D listens on (option in the config file).

# Details #

  * NAT3D can be built with stderr debugging support enabled. To do this, please use the -DDEBUG flag in the Makefile (Mac/Linux/UNIX only).



# Bridging  <font color='red'>(deprecated) - no longer required</font> #

> <font color='red'> NAT3D now automates the process of sending packets/receiving to/from other hosts.</font>

To make other machines behind the NAT box accessible to NAT3D, and effectively to external hosts, you may need to create a [software bridge](Bridge.md) between the TAP device and your internet interface.

Back to [introduction](Introduction.md).