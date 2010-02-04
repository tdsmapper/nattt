#!/usr/bin/perl

use strict;
use IO::Socket::UNIX;

use constant {
    SOCK_PATH => '/tmp/nat3.sock',
    MAGIC => 322423550, # 0x1337cafe
};

my $ip = inet_aton $ARGV[0] || die "No IP address given\n";
my $mesg = pack('N', MAGIC) . $ip;

my $unix_socket = IO::Socket::UNIX->new(
    Peer => SOCK_PATH,
    Type => SOCK_DGRAM,
) || die "Cannot create unix socket: $!\n";

$unix_socket->send($mesg, 8, 0) || die "Can't write message: $!\n";
