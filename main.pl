#!/usr/bin/perl
 
use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;

# enable autoflush to terminal
$| = 1;
open my $log,'>>','domain.log';
 
sub reply_handler {
  my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
  my $rdata = "";
  my ($rcode, @ans, @auth, @add);
  my $action = "lookup";

  print $log "* $qname ($qtype) from $peerhost ";

  if ($qtype ne "A") {
    $action = 'nxdomain';
  }

  if ($qname !~ /\./) {
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
    if ($rdata ne "") {
      my $ret = new Net::DNS::RR("$qname 3600 $qclass $qtype $rdata");
      push @ans, $ret;
      $rcode = "NOERROR";
      print '.';
      print $log "-> $rdata ($qtype)\n";
    } else {
      $rcode = "NXDOMAIN";
      print 'x';
      print $log "-> A entry not found\n";
    }
  } elsif ($action eq "forward") {
    my $ret = new Net::DNS::RR("$qname 3600 $qclass A 80.76.124.4"); 
    push @ans, $ret;
    $rcode = "NOERROR";
    print 'ˆ';
    print $log "-> $action\n";
  } else {
    print '!';
    $rcode = "NXDOMAIN";
    print $log "-> $action\n"; 
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

close $log;
