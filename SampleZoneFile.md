The name of the zone is _nattt_. So the server names are _xyz.nattt_


## named.conf ##

```
// If you are just adding zones, please do that in /etc/bind/named.conf.local
include "/etc/bind/named.conf.options";

// prime the server with knowledge of the root servers
zone "." {
	type hint;
	file "/etc/bind/db.root";
};
// be authoritative for the localhost forward and reverse zones, and for
// broadcast zones as per RFC 1912
zone "localhost" {
	type master;
	file "/etc/bind/db.local";
};
zone "127.in-addr.arpa" {
	type master;
	file "/etc/bind/db.127";
};
zone "0.in-addr.arpa" {
	type master;
	file "/etc/bind/db.0";
};
zone "255.in-addr.arpa" {
	type master;
	file "/etc/bind/db.255";
};
include "/etc/bind/named.conf.local";
```

## named.conf.local ##
```
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

# This is the zone definition. replace example.com with your domain name
zone "nattt" {
	type master;
	file "/etc/bind/zones/nattt.db";
};
```

### zones/nattt.db ###
```
$TTL 1
nattt.      IN      SOA     localhost. localhost. (
      2006081401
      28800
      3600
      604800
      38400
      )
nattt. NS 127.0.0.1
b.nattt. IN TYPE65324 \# 10 55 b0 22 63 00 67 0a 00 00 11
```