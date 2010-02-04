#!/usr/bin/perl -w

use strict;

use File::Copy;

sub _usage
{
  print("resolv-roll.pl [<config file>] | [-h]\n");
}

sub _config_update
{
  my $p_sConfig = shift;
  my $p_sRes = shift;

  my $bRet = 0;

  if (!defined($p_sConfig))
  {
    warn("No config file specified.");
  }
  elsif (!defined($p_sRes))
  {
    warn("No resolver defined.");
  }
  elsif (!open(CONF, "< $p_sConfig"))
  {
    warn("Unable to open config file: $p_sConfig");
  }
  else
  {
    my @lConf;
    my $sLine = undef;
    while ($sLine = <CONF>)
    {
      if ($sLine !~ /^\s*resolver\s*=.*$/)
      {
        push(@lConf, $sLine);
      }
    }
    push(@lConf, "resolver = $p_sRes\n");
    close(CONF);

    if (!open(CONF, "> $p_sConfig"))
    {
      warn("Unable to open config file for writing: $p_sConfig");
    }
    else
    {
      while ($sLine = shift(@lConf))
      {
        print(CONF $sLine);
      }
      close(CONF);
      $bRet = 1;
    }
  }

  return $bRet;
}

my $sConfig = shift;

if (!defined($sConfig))
{
  $sConfig = "/etc/nat3.conf";
}

my $sTmp = "/tmp/resolv.conf-" . time() . ".tmp";

if ("-h" eq $sConfig)
{
  _usage();
}
elsif (!open(RES, "< /etc/resolv.conf"))
{
  warn("Unable to read '/etc/resolv.conf'");
}
elsif (!open(TMP, "> $sTmp"))
{
  warn("Unable to open tempfile: $sTmp");
  close(RES);
}
else
{
  my $sOldRes = 
  my $sLine = undef;
  while ($sLine = <RES>)
  {
    if ($sLine =~ m/\s*nameserver\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$/)
    {
      my $sTmp = $1;
      if ($sTmp ne "127.0.0.1" && !defined($sOldRes))
      {
        $sOldRes = $1;
        chomp($sOldRes);
      }
    }
    else
    {
      print(TMP $sLine);
    }
  }
  close(RES);

  print(TMP "nameserver 127.0.0.1\n");
  close(TMP);

  if (!defined($sOldRes))
  {
    warn("Unable to find old resolver?");
  }
  elsif (!_config_update($sConfig, $sOldRes))
  {
    warn("Unable to update config file.");
  }
  elsif (!copy($sTmp, "/etc/resolv.conf"))
  {
    warn("Unable to overcopy /etc/resolv.conf... Are you root?");
  }

  unlink($sTmp);
}
