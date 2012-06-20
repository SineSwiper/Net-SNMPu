use sanity;
use Test::More;

plan tests => 15;

use Net::SNMPu::Dispatcher;
use Net::SNMPu::Transport;

#
# 1. Create transmit and receive Transport Domain objects
#

my ($r, $tr, $ts) = (100);

eval
{
   while ((!defined $tr || !defined $ts) && $r-- > 0) {
      my $p = (int rand(65535 - 1025)) + 1025;
      $tr = Net::SNMPu::Transport->new(-localport => $p);
      $ts = Net::SNMPu::Transport->new(-port => $p);
   }
};

ok(
   defined $tr && defined $ts, 1,
   'Failed to create Net::SNMPu::Transport objects'
);

#
# 2. Get the Dispatcher instance
#

my $d;

eval
{
   $d = Net::SNMPu::Dispatcher->instance();
};

ok(defined $d, 1, 'Failed to get the Net::SNMPu::Dispatcher instance');

#
# 3. Register the receive Transport Domain object
#

eval
{
   $r = $d->register($tr, [\&trans_recv]);
};

ok($r, $tr, 'Failed to register receive transport - trans_recv()');

#
# 4. Schedule timer test 1 - timer_test()
#

eval
{
   $r = $d->schedule(1, [\&timer_test, 1, time]);
};

ok(defined $r, 1, 'Failed to schedule timer test 1 - timer_test()');

#
# 5. Schedule timer test 2 - timer_test()
#

eval
{
   $r = $d->schedule(2, [\&timer_test, 2, time]);
};

ok(defined $r, 1, 'Failed to schedule timer test 2 - timer_test()');

#
# 6. Schedule timer test 3 - trans_send()
#

eval
{
   $r = $d->schedule(3, [\&trans_send, 3, time, $ts]);
};

ok(defined $r, 1, 'Failed to schedule timer test 3 - trans_send()');

#
# 7. Schedule timer test 4 - trans_dereg()
#

eval
{
   $r = $d->schedule(4, [\&trans_dereg, 4, time, $tr]);
};

ok(defined $r, 1, 'Failed to schedule timer test 4 - trans_dereg()');


$d->loop();

exit 0;

#
# 8. - 9. Validate that timer tests 1 and 2 executed within 1 second tolerence 
#

sub timer_check
{
   my ($c, $s) = @_;

   my $d = time - $s;

   return (($d >= $c - 1) && ($d <= $c + 1)) ? $c : $d;
}

sub timer_test
{
   my ($d, $c, $s) = @_;

   ok(timer_check($c, $s), $c, "timer_test(): Timer test $c failed");

   return;
}

#
# 10. - 11. Validate timer test 3 and Net::SNMPu::Transport->send()
#

sub trans_send
{
   my ($d, $c, $s, $t) = @_;

   ok(timer_check($c, $s), $c, "trans_send(): Timer test $c failed");

   $c = $t->send(' ');

   ok($c, 1, 'trans_send(): Transport send() failed');

   return;
}

#
# 12. - 13. Validate the transport registration and transport recv()
#

sub trans_recv
{
   my ($d, $t) = @_;

   ok(defined $t, 1, 'trans_recv(): Transport registration failed');

   my $b;

   my $c = $t->recv($b, 10, 0);

   ok(defined $c, 1, 'trans_recv(): Transport recv() failed');

   return;
}

#
# 14. - 15. Validate timer test 4 and transport deregistration
#

sub trans_dereg
{
   my ($d, $c, $s, $t) = @_;

   ok(timer_check($c, $s), $c, "trans_dereg(): Timer test $c failed");

   $c = $d->deregister($t);

   ok($c, $t, 'trans_dereg(): Failed to deregister receive transport');

   return;
}

# ============================================================================
