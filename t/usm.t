use sanity;
use Test::More;

plan tests => 14

use Net::SNMPu::Message qw(SEQUENCE OCTET_STRING FALSE);

#
# Load the Net::SNMPu::Security::USM module
#

eval 'use Net::SNMPu::Security::USM';

my $skip = ($@ =~ /locate (:?\S+\.pm)/) ? $@ : FALSE;

#
# 1. Create the Net::SNMPu::Security::USM object
#

my ($u, $e);

eval
{
   ($u, $e) = Net::SNMPu::Security::USM->new(
      -username     => 'dtown',
      -authpassword => 'maplesyrup',
      -privpassword => 'maplesyrup',
      -privprotocol => 'des',
   );

   # "Perform" discovery...
   $u->_engine_id_discovery(pack 'x11H2', '02');

   # ...and synchronization
   $u->_synchronize(10, time);
};

skip(
   $skip, ($@ || $e), q{}, 'Failed to create Net::SNMPu::Security::USM object'
);

#
# 2. Check the localized authKey
#

eval
{
   $e = unpack 'H*', $u->auth_key();
};

skip(
   $skip,
   ($@ || $e),
   '526f5eed9fcce26f8964c2930787d82b', # RFC 3414 - A.3.1
   'Invalid authKey calculated'
);

#
# 3. Check the localized privKey
#

eval
{
   $e = unpack 'H*', $u->priv_key();
};

skip(
   $skip,
   ($@ || $e),
   '526f5eed9fcce26f8964c2930787d82b',
   'Invalid privKey calculated'
);

#
# 4. Create and initalize a Message
#

my $m;

eval
{
   ($m, $e) = Net::SNMPu::Message->new();
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8);
   $e = $m->error();
};

skip($skip, ($@ || $e), q{}, 'Failed to create Net::SNMPu::Message object');

#
# 5. Calculate the HMAC
#

my $h;

eval
{
   $h = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, $@, q{}, 'Calculate the HMAC failed');

#
# 6. Encrypt/descrypt the Message
#

eval
{
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
};

skip($skip, ($@ || $e), q{}, 'Privacy failed');

#
# 7. Check the HMAC
#

my $h2;

eval
{
   $h2 = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, ($@ || $h2), $h, 'Authentication failed');

#
# 8. Create the Net::SNMPu::Security::USM object
#

eval
{
   ($u, $e) = Net::SNMPu::Security::USM->new(
      -username     => 'dtown',
      -authpassword => 'maplesyrup',
      -authprotocol => 'sha',
      -privpassword => 'maplesyrup',
      -privprotocol => 'des',
   );

   # "Perform" discovery...
   $u->_engine_id_discovery(pack 'x11H2', '02');

   # ...and synchronization
   $u->_synchronize(10, time);
};

skip(
   $skip, ($@ || $e), q{}, 'Failed to create Net::SNMPu::Security::USM object'
);

#
# 9. Check the localized authKey
#

eval
{
   $e = unpack 'H*', $u->auth_key();
};

skip(
   $skip,
   ($@ || $e),
   '6695febc9288e36282235fc7151f128497b38f3f', # RFC 3414 - A.3.2
   'Invalid authKey calculated'
);

#
# 10. Check the localized privKey
#

eval
{
   $e = unpack 'H*', $u->priv_key();
};

skip(
   $skip,
   ($@ || $e),
   '6695febc9288e36282235fc7151f1284',
   'Invalid privKey calculated'
);

#
# 11. Create and initalize a Message
#

eval
{
   ($m, $e) = Net::SNMPu::Message->new();
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8);
   $e = $m->error();
};

skip($skip, ($@ || $e), q{}, 'Failed to create Net::SNMPu::Message object');

#
# 12. Calculate the HMAC
#

eval
{
   $h = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, $@, q{}, 'Calculate the HMAC failed');

#
# 13. Encrypt/descrypt the Message
#

eval
{
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
};

skip($skip, ($@ || $e), q{}, 'Privacy failed');

#
# 14. Check the HMAC
#

eval
{
   $h2 = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, ($@ || $h2), $h, 'Authentication failed');

# ============================================================================
