use sanity;
use Devel::SimpleTrace;
use Net::SNMPu;

use Test::More tests => 2;

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

isa_ok( $session->open, 'Net::SNMPu::Transport', 'open object === Transport' );

use Devel::Dwarn;
Dwarn $session;
