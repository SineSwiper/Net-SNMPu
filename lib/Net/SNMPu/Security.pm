package Net::SNMPu::Security;

# ABSTRACT: Base object that implements the Net::SNMPu Security Models.

use sanity;
use Class::Load;

## Handle importing/exporting of symbols

use Net::SNMPu::Message;
use Net::SNMPu::Constants qw(
   :securityLevels :securityModels :versions :bool
);

## Package variables

our $DEBUG = FALSE;  # Debug flag
our $AUTOLOAD;       # Used by the AUTOLOAD method

# [public methods] -----------------------------------------------------------

sub new {
   my ($class, %argv) = @_;

   my $version = SNMP_VERSION_1;

   # See if a SNMP version has been passed
   for (keys %argv) {
      if (/^-?version$/i) {
         if (($argv{$_} == SNMP_VERSION_1)  ||
             ($argv{$_} == SNMP_VERSION_2C) ||
             ($argv{$_} == SNMP_VERSION_3))
         {
            $version = $argv{$_};
         }
      }
   }

   # Return the appropriate object based upon the SNMP version.  To
   # avoid consuming unnecessary resources, only load the appropriate
   # module when requested.   The Net::SNMPu::Security::USM module
   # requires four non-core modules.  If any of these modules are not
   # present, we gracefully return an error.

   if ($version == SNMP_VERSION_3) {
      my ($s, $error) = Class::Load::try_load_module('Net::SNMPu::Security::USM');
      if ($error) {
         $error = 'SNMPv3 support is unavailable ' . $error;
         return wantarray ? (undef, $error) : undef;
      }

      return Net::SNMPu::Security::USM->new(%argv);
   }

   # Load the default Security module without eval protection.

   require Net::SNMPu::Security::Community;
   return  Net::SNMPu::Security::Community->new(%argv);
}

sub version {
   my ($this) = @_;

   if (@_ > 1) {
      $this->_error_clear();
      return $this->_error('The SNMP version is not modifiable');
   }

   return $this->{_version};
}

use constant {
   discovered     => TRUE,
   security_model => SECURITY_MODEL_ANY,           # RFC 3411 - SnmpSecurityModel::=TEXTUAL-CONVENTION
   security_level => SECURITY_LEVEL_NOAUTHNOPRIV,  # RFC 3411 - SnmpSecurityLevel::=TEXTUAL-CONVENTION
   security_name  => q{},
};

sub debug {
   return (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

sub error {
   return $_[0]->{_error} || q{};
}

sub AUTOLOAD {
   my ($this) = @_;

   return if $AUTOLOAD =~ /::DESTROY$/;

   $AUTOLOAD =~ s/.*://;

   if (ref $this) {
      $this->_error_clear();
      return $this->_error(
         'The method "%s" is not supported by this Security Model', $AUTOLOAD
      );
   } else {
      require Carp;
      Carp::croak(sprintf 'The function "%s" is not supported', $AUTOLOAD);
   }

   # Never get here.
   return;
}

# [private methods] ----------------------------------------------------------

sub _error {
   my $this = shift;

   if (!defined $this->{_error}) {
      $this->{_error} = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0];
      if ($this->debug()) {
         printf "error: [%d] %s(): %s\n",
                (caller 0)[2], (caller 1)[3], $this->{_error};
      }
   }

   return;
}

sub _error_clear {
   return $_[0]->{_error} = undef;
}

sub err_msg {
   my $msg = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0];

   if ($DEBUG) {
      printf "error: [%d] %s(): %s\n", (caller 0)[2], (caller 1)[3], $msg;
   }

   return $msg;
}

sub DEBUG_INFO {
   return if (!$DEBUG);

   return printf
      sprintf('debug: [%d] %s(): ', (caller 0)[2], (caller 1)[3]) .
      ((@_ > 1) ? shift(@_) : '%s') .
      "\n",
      @_;
}

# ============================================================================
1; # [end Net::SNMPu::Security]

