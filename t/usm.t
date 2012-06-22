use Test::Most;
use Class::Load;
use sanity;

use Net::SNMPu::Message qw(SEQUENCE OCTET_STRING FALSE);

#
# Load the Net::SNMPu::Security::USM module
#

my ($s, $error) = Class::Load::try_load_class('Net::SNMPu::Security::USM');
if ($error) {
   die 'Class load failure for Net::SNMPu::Security::USM: '.$error
      unless ($error =~ /Can't locate \(:?\S+\.pm\) in \@INC/);
   plan skip_all => "Net::SNMPu::Security::USM doesn't have the required modules";
}
plan tests => 34;
pass('Net::SNMPu::Security::USM loaded');
my ($u, $e);

#
# 1. Create the Net::SNMPu::Security::USM object
#

($u, $e) = Net::SNMPu::Security::USM->new(
   -username     => 'dtown',
   -authpassword => 'maplesyrup',
   -privpassword => 'maplesyrup',
   -privprotocol => 'des',
);
isa_ok($u, 'Net::SNMPu::Security::USM');
is($e, '', 'No error on USM->new()');

# "Perform" discovery...
$u->_engine_id_discovery(pack 'x11H2', '02');
is($u->error(), '', 'No error on USM->_engine_id_discovery()');

# ...and synchronization
$u->_synchronize(10, time);
is($u->error(), '', 'No error on USM->_synchronize()');

#
# 2. Check the localized authKey
#

is(
   unpack('H*', $u->auth_key()),
   '526f5eed9fcce26f8964c2930787d82b',  # RFC 3414 - A.3.1
   'Correct authKey calculated',
);
is($u->error(), '', 'No error on USM->auth_key()');

#
# 3. Check the localized privKey
#

is(
   unpack('H*', $u->priv_key()),
   '526f5eed9fcce26f8964c2930787d82b',
   'Correct privKey calculated'
);
is($u->error(), '', 'No error on USM->priv_key()');

#
# 4. Create and initalize a Message
#

my $m;

($m, $e) = Net::SNMPu::Message->new();
isa_ok($m, 'Net::SNMPu::Message');
is($e, '', 'No error on Message->new()');

$m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8);
is($m->error(), '', 'No error on Message->prepare(SEQUENCE)');

#
# 5. Calculate the HMAC
#
my ($h, $h2);
ok(
   ( $h = unpack('H*', $u->_auth_hmac($m)) ),
   'HMAC calculated'
);
is($u->error(), '', 'No error on USM->_auth_hmac()');

#
# 6. Encrypt/decrypt the Message
#

can_ok($m, qw(length clear append process reference));
can_ok($u, qw(_encrypt_data _decrypt_data error));

lives_ok {
   my $salt;
   my $len = $m->length();
   my $buff = $m->clear();
   $m->append($u->_encrypt_data($m, $salt, $buff));
   $u->_decrypt_data($m, $salt, $m->process(OCTET_STRING));
   $e = $u->error();
   # Remove padding if necessary
   if ($len -= $m->length()) {
      substr ${$m->reference()}, $len, -$len, q{};
   }
} 'Encrypt/decrypt privacy (1st test)';
is($u->error(), '', 'No error on USM->_decrypt_data()');

#
# 7. Check the HMAC
#

ok(
   ( $h2 = unpack('H*', $u->_auth_hmac($m)) ),
   'Authentication failed'
);
is($u->error(), '', 'No error on USM->_auth_hmac()');
is($h2, $h, 'HMAC->HMAC matches');

#
# 8. Create the Net::SNMPu::Security::USM object
#

($u, $e) = Net::SNMPu::Security::USM->new(
   -username     => 'dtown',
   -authpassword => 'maplesyrup',
   -authprotocol => 'sha',
   -privpassword => 'maplesyrup',
   -privprotocol => 'des',
);
isa_ok($u, 'Net::SNMPu::Security::USM');
is($e, '', 'No error on USM->new(SHA)');

# "Perform" discovery...
$u->_engine_id_discovery(pack 'x11H2', '02');

# ...and synchronization
$u->_synchronize(10, time);

#
# 9. Check the localized authKey
#
is(
   unpack('H*', $u->auth_key()),
   '6695febc9288e36282235fc7151f128497b38f3f',  # RFC 3414 - A.3.2
   'Correct SHA authKey calculated',
);

#
# 10. Check the localized privKey
#

is(
   unpack('H*', $u->priv_key()),
   '6695febc9288e36282235fc7151f1284',
   'Correct privKey calculated (auth SHA)'
);

#
# 11. Create and initalize a Message
#

($m, $e) = Net::SNMPu::Message->new();
isa_ok($m, 'Net::SNMPu::Message');
is($e, '', 'No error on Net::SNMPu::Message->new()');

$m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8);
$e = $m->error();
is($e, '', 'Still no error after prepare(SEQUENCE)');

#
# 12. Calculate the HMAC
#

ok(
   ( $h = unpack('H*', $u->_auth_hmac($m)) ),
   'HMAC calculated (SHA)'
);

#
# 13. Encrypt/decrypt the Message
#

can_ok($m, qw(length clear append process reference));
can_ok($u, qw(_encrypt_data _decrypt_data error));

lives_ok {
   my $salt;
   my $len = $m->length();
   my $buff = $m->clear();
   $m->append($u->_encrypt_data($m, $salt, $buff));
   $u->_decrypt_data($m, $salt, $m->process(OCTET_STRING));
   $e = $u->error();
   # Remove padding if necessary
   if ($len -= $m->length()) {
      substr ${$m->reference()}, $len, -$len, q{};
   }
} 'Encrypt/decrypt privacy (SHA)';

#
# 14. Check the HMAC
#

ok(
   ( $h2 = unpack('H*', $u->_auth_hmac($m)) ),
   'Authentication failed (SHA)'
);
is($h2, $h, 'HMAC->HMAC matches (SHA)');

# ============================================================================
