use sanity;
use Test::More;
use Devel::SimpleTrace;
use Net::SNMPu;

my $session = new_ok( 'Net::SNMPu' => [
   hostname      => 'localhost',
   localaddr     => 'localhost',
   localport     => 55555 + int(rand(100)),
   non_blocking  => 0,
   version       => 2,
   domain        => 'udp',
   timeout       => 5,
   retries       => 2,
   max_msg_size  => 32767,
   debug         => 255,
   community     => 'public',
], 'create new Net::SNMPu object');
