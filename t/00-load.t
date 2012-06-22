use sanity;
use Test::More;
use version;

plan tests => 1;

BEGIN {
   use_ok( 'Net::SNMPu' ) || print "Bail out!\n";
}

diag( 
   sprintf("Testing %s %s, Perl %s (%s)", 'Net::SNMPu', (map { version->parse($_)->normal } ($Net::SNMPu::VERSION, $])), $^X)
);
