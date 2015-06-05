# Installation #

## Step 1: Download ##
Download via SVN.
```
svn checkout http://nattt.googlecode.com/svn/branch/tdsmapper/nat3/ support-read-only  
```

## Step 2: Build/Run ##

Please choose your operating system for detailed instructions on how to install and set up NAT3D on your machine:

  1. [Windows 2000 or later](WindowsInstallation.md)
  1. [Mac OS X/UNIX](OSXInstallation.md)
  1. [Linux](LinuxInstallation.md)

## Step 3: Set resolver to local machine ##

You need to set up your machine as the local resolver. The NAT3D listens on the DNS port and handles all DNS queries.

NAT3D will take over handling DNS queries i.e. all DNS queries from applications on your machine are sent to NAT3D, which sends them to the actual DNS server.

### Linux/UNIX/Mac: ###

There is a script _resolv-roll.pl_ that will update config file of NAT3D to reflect the new resolver, and also update /etc/resolv.conf

### Windows: ###

This needs to be done manually. No automation has been developed for this.

Good instructions for changing the resolver are found at: http://code.google.com/speed/public-dns/docs/using.html. You need to use the IP address 127.0.0.1 instead of the google server addresses.

Back to [introduction](Introduction.md).