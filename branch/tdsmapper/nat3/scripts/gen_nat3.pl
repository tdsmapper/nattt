#!/usr/bin/perl

use strict;
use Socket;

die "Usage: $0 <name> <external> <port> <internal>\n" unless @ARGV >= 4;

my ($name, $ext, $port, $int) = @ARGV;

my $num = type_number();

my $e = encode_ip($ext);
my $i = encode_ip($int);
my $p = encode_port($port);

print join (' ', $name, 'IN', "TYPE$num", '\# 10', $e, $p, $i), "\n";

sub type_number {
    my $ret;


    my $file = find_header();

    open my $src, '<', $file or die "Cannot open header file\n";
    while (<$src>) {
        if (/#define\s+DNS_RR_NAT3\s+(\d+)/) {
            $ret = $1;
            last;
        }
    }
    close $src;

    die "Couldn't find numeric type of NAT3\n" unless defined $ret;
    return $ret;
}

sub find_header {
    my @paths = qw(. .. ../src);

    foreach my $path (@paths) {
        return "$path/dns_rr.h" if -e "$path/dns_rr.h";
    }

    die "Unable to find dns_rr.h\n";
}

sub encode_ip {
    my $ip = inet_aton($_[0]) or die "$_[0] is not a valid IP address\n";
    return join ' ', (unpack 'H2 H2 H2 H2', $ip);
}

sub encode_port {
    return join ' ', (unpack 'H2 H2', (pack 'n', $_[0]));
}
