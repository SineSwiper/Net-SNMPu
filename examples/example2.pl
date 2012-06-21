#!perl

use sanity;
use Net::SNMPu;

my $OID_sysContact = '1.3.6.1.2.1.1.4.0';

my ($session, $error) = Net::SNMPu->session(
   -hostname     => 'myv3host.example.com',
   -version      => 'snmpv3',
   -username     => 'myv3Username',
   -authprotocol => 'sha1',
   -authkey      => '0x6695febc9288e36282235fc7151f128497b38f3f',
   -privprotocol => 'des',
   -privkey      => '0x6695febc9288e36282235fc7151f1284',
);

if (!defined $session) {
   printf "ERROR: %s.\n", $error;
   exit 1;
}

my $result = $session->set_request(
   -varbindlist => [ $OID_sysContact, OCTET_STRING, 'Help Desk x911' ],
);

if (!defined $result) {
   printf "ERROR: %s.\n", $session->error();
   $session->close();
   exit 1;
}

printf "The sysContact for host '%s' was set to '%s'.\n",
       $session->hostname(), $result->{$OID_sysContact};

$session->close();

exit 0;

# ============================================================================

