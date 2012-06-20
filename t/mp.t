use sanity;
use Test::More;

plan tests => 7;

use Net::SNMPu::MessageProcessing;
use Net::SNMPu::PDU qw( OCTET_STRING SNMP_VERSION_2C );
use Net::SNMPu::Security;
use Net::SNMPu::Transport;

#
# 1. Get the Message Processing instance 
#

my $m;

eval
{
   $m = Net::SNMPu::MessageProcessing->instance();
};

ok(defined $m, 1, 'Failed to get Net::SNMPu::MessageProcessing instance');

#
# 2. Create a Security object
#

my ($s, $e);

eval
{
   ($s, $e) = Net::SNMPu::Security->new(-version => SNMP_VERSION_2C);
};

ok(($@ || $e), q{}, 'Failed to create Net::SNMPu::Security object');

#
# 3. Create a Transport Layer object
#

my $t;

eval
{
   ($t, $e) = Net::SNMPu::Transport->new();
};

ok(($@ || $e), q{}, 'Failed to create Net::SNMPu::Transport object');

#
# 4. Create a PDU object
#

my $p;

eval
{
   ($p, $e) = Net::SNMPu::PDU->new(
      -version   => SNMP_VERSION_2C,
      -transport => $t,
      -security  => $s,
   );
};

ok(($@ || $e), q{}, 'Failed to create Net::SNMPu::PDU object');

#
# 5. Prepare the PDU
#

eval
{
   $p->prepare_set_request(['1.3.6.1.2.1.1.4.0', OCTET_STRING, 'dtown']);
   $e = $p->error();
};

ok(($@ || $e), q{}, 'Failed to prepare set-request');

#
# 6. Prepare the Message
#

eval
{
   $p = $m->prepare_outgoing_msg($p);
   $e = $m->error();
};

ok(($@ || $e), q{}, 'Failed to prepare Message');

#
# 7. Process the message (should get error)
#

eval
{
   $m->prepare_data_elements($p);
   $e = $m->error();
};

ok(($@ || $e), qr/expected/i, 'Failed to process Message');

# ============================================================================
