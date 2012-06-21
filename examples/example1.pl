#!perl

use sanity;
use Net::SNMPu;

my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';

my ($session, $error) = Net::SNMPu->session(
   -hostname  => shift || 'localhost',
   -community => shift || 'public',
);

if (!defined $session) {
   printf "ERROR: %s.\n", $error;
   exit 1;
}

my $result = $session->get_request(-varbindlist => [ $OID_sysUpTime ],);

if (!defined $result) {
   printf "ERROR: %s.\n", $session->error();
   $session->close();
   exit 1;
}

printf "The sysUpTime for host '%s' is %s.\n",
       $session->hostname(), $result->{$OID_sysUpTime};

$session->close();

exit 0;

# ============================================================================

