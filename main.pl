#!/usr/bin/perl
 
use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
 
sub reply_handler {
  my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
  my ($rdata, $rcode, @ans, @auth, @add);
  my $action = "lookup";

  print "* $qname ($qtype) from $peerhost ";

  if ($qtype ne "A") {
    $action = 'nxdomain';
  }

  if ($qname =~ /(sex)|(porn)/) {
    $action = 'forward';
  }
 
  if ($action eq "lookup") {
    my $res = Net::DNS::Resolver->new(
      nameservers => [qw(8.8.8.8 8.8.4.4)],
      recurse     => 1,
      debug       => 0,
    );
    $query = $res->search($qname,$qtype);
    if ($query) {
      foreach my $rr ($query->answer) {
        next unless $rr->type eq "A";
        $rdata = $rr->address;
        $qtype = $rr->type;
      }
    }
    if ($qtype eq "A") {
      my $ret = new Net::DNS::RR("$qname 3600 $qclass $qtype $rdata");
      push @ans, $ret;
      $rcode = "NOERROR";
      print "-> $rdata ($qtype)\n";
    } else {
      $rcode = "NXDOMAIN";
      print "-> A entry not found\n";
    }
  } elsif ($action eq "forward") {
    my $ret = new Net::DNS::RR("$qname 3600 $qclass A 80.76.124.4"); 
    push @ans, $ret;
    $rcode = "NOERROR";
    print "-> $action\n";
  } else {
    $rcode = "NXDOMAIN";
    print "-> $action\n"; 
  }

  # mark the answer as authoritive (by setting the 'aa' flag
  return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}
 
my $ns = new Net::DNS::Nameserver(
    LocalPort    => 53,
    ReplyHandler => \&reply_handler,
    Verbose      => 0
    ) || die "couldn't create nameserver object\n";
 
$ns->main_loop;
