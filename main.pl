#!/usr/bin/perl
 
use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
 
sub reply_handler {
  my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
  my ($rdata, $rcode, @ans, @auth, @add);
  my $filter = "ok";

  print "* $qname ($qtype) from $peerhost ";

  if ($qname =~ /(sex)|(porn)/) {
    $filter = 'skip';
  }
 
  if ($filter eq "ok") {

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
      }
    }

    if ($rdata ne "") {
      my $ret = new Net::DNS::RR("$qname 3600 $qclass $qtype $rdata");
      push @ans, $ret;
      $rcode = "NOERROR";
      print "-> $rdata ($qtype)\n";
    } else {
      $rcode = "NXDOMAIN";
      print "-> nada\n";
    }
  } else {
   my $ret = new Net::DNS::RR("$qname 3600 $qclass A 199.181.132.249"); 
   push @ans, $ret;
   $rcode = "NOERROR";
   print "-> filtered\n";
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
