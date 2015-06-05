# Introduction #

There is a dynamic DNS system that comes with BIND9. `nsupdate` is the program.

Sample code of how to update a DNS record

```
nsupdate
> server xyz.com
> zone nattt
> update add 5.nattt. 1 TYPE65324 \# 10 xx xx xx xx 26 94 0a 00 00 05     
> show
> send
```

Where xx represent the external IP address.

Where 5.nattt is the domain name.

\# 10 represents size of following data. xx xx xx xx is external IP. 26 94 is the port number 9876. 0a 00 00 05 is the address within the NAT.

It is further described [here](http://code.google.com/p/nat3d-dns/wiki/CustomRecord).