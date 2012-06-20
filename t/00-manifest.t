#!perl
use sanity;
use Test::More;
use Class::Load;

unless ( $ENV{RELEASE_TESTING} ) {
   plan( skip_all => "Author tests not required for installation" );
}

# auto-fail if RELEASE_TESTING
Class::Load->load_class('Test::CheckManifest', 0.9);

ok_manifest();
