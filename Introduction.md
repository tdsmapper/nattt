# Introduction #
NATTT or NAT3D is a NAT box traversal solution. It requires no change to the server, client or the NAT box, and only expects some minimal behavior (port forwarding).

# Brief description of working #

NAT3D is set to resolve DNS queries on the local machine. The resolver you use for regular queries is set in the NAT3Ds [config file](ConfigFile.md). All DNS queries are sent to the resolver and the reply is sent back to the querying application. When NAT3D kicks in is when a DNS server returns "Domain not found" as a responses. In that case, NAT3D issues a custom query, and with the response to that query, is able to tunnel packets to the NAT3D application running as server behind a NAT box, which decapsulates and forwards the packet to the machine behind the NAT box.

Read on on how to set up NATTT for more details.

For a more pictorial description, view the [flowchart](NATTTFlowchart.md).


# Overview of solution #

Our NAT traversal design aims to achieve two main goals. First, the solution should be generic. It should support all applications and transport protocols, and it should also support nested NATs. Second, it should be incrementally deployable. It should be compatible with existing infrastructures, including NAT boxes, hosts, and applications, and the cost and gains of deploying the solution should align at the same place.

The basic idea is to tunnel packets through NAT boxes to restore end-to-end reachability. Suppose an external host A wants to initiate communication with an internal host B behind a NAT box Y. If A knows both Y's public address (Ypub) and B's private address, A can tunnel packets to B as follows. The outer header of a packet is destined to Ypub, so that the packet can be routed over the public Internet to reach Y; The inner header is addressed to B, so that when Y receives the packet, it can remove the outer header and find out where to forward the packet within the private network.

![http://www.cs.arizona.edu/~bzhang/nat/figures/portforward.png](http://www.cs.arizona.edu/~bzhang/nat/figures/portforward.png)

Complete details are found [here](http://www.cs.arizona.edu/~bzhang/nat/nattt.htm).

# List of pages on wiki #

## Man/User pages ##

  * [Installation](Installation.md)
  * [Running NAT3D](RunningNATTT.md)
  * [Resolver Setup](ResolverSetup.md)
  * [Errors](Errors.md) faced with NAT3D.

## Development pages ##
  * [Devel pages](DeveloperPages.md)
  * [Flowchart of application](NATTTFlowchart.md)