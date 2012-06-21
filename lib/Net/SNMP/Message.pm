package Net::SNMPu::Message;

# ABSTRACT: Object used to represent a SNMP message. 

use sanity;
use bytes;

use Math::BigInt();

our $XS = 0;

BEGIN {
   my $loader = Module::Implementation::build_loader_sub(
      implementations => [ $ENV{PERL_NETSNMPU_MESSAGE_PP} ? ('PP') : qw(XS PP) ],
      symbols         => [
         qw(index process oid_base_match oid_lex_cmp oid_lex_sort),
         (map { "_process_$_" } qw(length integer32 octet_string object_identifier sequence ipaddress counter gauge timeticks opaque counter64)),
         qw(_buffer_append _buffer_get),
      ],
   );
 
   $loader->();
}

# Set types for the XS version
if (Module::Implementation::implementation_for(__PACKAGE__) eq 'XS') {
   $XS = 1;
   __PACKAGE__::XS::set_type INTEGER          , \&_process_integer32;
   __PACKAGE__::XS::set_type OCTET_STRING     , \&_process_octet_string;
   __PACKAGE__::XS::set_type NULL             , \&_process_null;
   __PACKAGE__::XS::set_type OBJECT_IDENTIFIER, \&_process_object_identifier;
   __PACKAGE__::XS::set_type SEQUENCE         , \&_process_sequence;
   __PACKAGE__::XS::set_type IPADDRESS        , \&_process_ipaddress;
   __PACKAGE__::XS::set_type COUNTER          , \&_process_counter;
   __PACKAGE__::XS::set_type GAUGE            , \&_process_gauge;
   __PACKAGE__::XS::set_type TIMETICKS        , \&_process_timeticks;
   __PACKAGE__::XS::set_type OPAQUE           , \&_process_opaque;
   __PACKAGE__::XS::set_type COUNTER64        , \&_process_counter64;
   __PACKAGE__::XS::set_type NOSUCHOBJECT     , \&_process_nosuchobject;
   __PACKAGE__::XS::set_type NOSUCHINSTANCE   , \&_process_nosuchinstance;
   __PACKAGE__::XS::set_type ENDOFMIBVIEW     , \&_process_endofmibview;
   __PACKAGE__::XS::set_type GET_REQUEST      , \&_process_get_request;
   __PACKAGE__::XS::set_type GET_NEXT_REQUEST , \&_process_get_next_request;
   __PACKAGE__::XS::set_type GET_RESPONSE     , \&_process_get_response;
   __PACKAGE__::XS::set_type SET_REQUEST      , \&_process_set_request;
   __PACKAGE__::XS::set_type TRAP             , \&_process_trap;
   __PACKAGE__::XS::set_type GET_BULK_REQUEST , \&_process_get_bulk_request;
   __PACKAGE__::XS::set_type INFORM_REQUEST   , \&_process_inform_request;
   __PACKAGE__::XS::set_type SNMPV2_TRAP      , \&_process_v2_trap;
   __PACKAGE__::XS::set_type REPORT           , \&_process_report;
}

### TODO: The rest of this stuff is only found as a PP version. ###

## Handle importing/exporting of symbols

use parent 'Exporter';
our @EXPORT_OK = qw( TRUE FALSE DEBUG_INFO );
our %EXPORT_TAGS = (
   generictrap    => [
      qw( COLD_START WARM_START LINK_DOWN LINK_UP AUTHENTICATION_FAILURE
          EGP_NEIGHBOR_LOSS ENTERPRISE_SPECIFIC )
   ],
   msgFlags       => [
      qw( MSG_FLAGS_NOAUTHNOPRIV MSG_FLAGS_AUTH MSG_FLAGS_PRIV 
          MSG_FLAGS_REPORTABLE MSG_FLAGS_MASK )
   ],
   securityLevels => [
      qw( SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV
          SECURITY_LEVEL_AUTHPRIV )
   ],
   securityModels => [
      qw( SECURITY_MODEL_ANY SECURITY_MODEL_SNMPV1 SECURITY_MODEL_SNMPV2C
          SECURITY_MODEL_USM )
   ],
   translate      => [
      qw( TRANSLATE_NONE TRANSLATE_OCTET_STRING TRANSLATE_NULL 
          TRANSLATE_TIMETICKS TRANSLATE_OPAQUE TRANSLATE_NOSUCHOBJECT 
          TRANSLATE_NOSUCHINSTANCE TRANSLATE_ENDOFMIBVIEW TRANSLATE_UNSIGNED 
          TRANSLATE_ALL )
   ],
   types          => [
      qw( INTEGER INTEGER32 OCTET_STRING NULL OBJECT_IDENTIFIER SEQUENCE
          IPADDRESS COUNTER COUNTER32 GAUGE GAUGE32 UNSIGNED32 TIMETICKS
          OPAQUE COUNTER64 NOSUCHOBJECT NOSUCHINSTANCE ENDOFMIBVIEW
          GET_REQUEST GET_NEXT_REQUEST GET_RESPONSE SET_REQUEST TRAP
          GET_BULK_REQUEST INFORM_REQUEST SNMPV2_TRAP REPORT )
   ],
   utilities      => [ qw( asn1_ticks_to_time asn1_itoa ) ],
   versions       => [ qw( SNMP_VERSION_1 SNMP_VERSION_2C SNMP_VERSION_3 ) ],
);

Exporter::export_ok_tags(
   qw( generictrap msgFlags securityLevels securityModels translate types 
       utilities versions )
);

$EXPORT_TAGS{ALL} = [ @EXPORT_OK ];

use constant {
   ## ASN.1 Basic Encoding Rules type definitions

   INTEGER                  => 0x02,  # INTEGER
   INTEGER32                => 0x02,  # Integer32           - SNMPv2c
   OCTET_STRING             => 0x04,  # OCTET STRING
   NULL                     => 0x05,  # NULL
   OBJECT_IDENTIFIER        => 0x06,  # OBJECT IDENTIFIER
   SEQUENCE                 => 0x30,  # SEQUENCE

   IPADDRESS                => 0x40,  # IpAddress
   COUNTER                  => 0x41,  # Counter
   COUNTER32                => 0x41,  # Counter32           - SNMPv2c
   GAUGE                    => 0x42,  # Gauge
   GAUGE32                  => 0x42,  # Gauge32             - SNMPv2c
   UNSIGNED32               => 0x42,  # Unsigned32          - SNMPv2c
   TIMETICKS                => 0x43,  # TimeTicks
   OPAQUE                   => 0x44,  # Opaque
   COUNTER64                => 0x46,  # Counter64           - SNMPv2c

   NOSUCHOBJECT             => 0x80,  # noSuchObject        - SNMPv2c
   NOSUCHINSTANCE           => 0x81,  # noSuchInstance      - SNMPv2c
   ENDOFMIBVIEW             => 0x82,  # endOfMibView        - SNMPv2c

   GET_REQUEST              => 0xa0,  # GetRequest-PDU
   GET_NEXT_REQUEST         => 0xa1,  # GetNextRequest-PDU
   GET_RESPONSE             => 0xa2,  # GetResponse-PDU
   SET_REQUEST              => 0xa3,  # SetRequest-PDU
   TRAP                     => 0xa4,  # Trap-PDU
   GET_BULK_REQUEST         => 0xa5,  # GetBulkRequest-PDU  - SNMPv2c
   INFORM_REQUEST           => 0xa6,  # InformRequest-PDU   - SNMPv2c
   SNMPV2_TRAP              => 0xa7,  # SNMPv2-Trap-PDU     - SNMPv2c
   REPORT                   => 0xa8,  # Report-PDU          - SNMPv3

   ## SNMP RFC version definitions

   SNMP_VERSION_1           => 0x00,  # RFC 1157 SNMPv1
   SNMP_VERSION_2C          => 0x01,  # RFC 1901 Community-based SNMPv2
   SNMP_VERSION_3           => 0x03,  # RFC 3411 SNMPv3

   ## RFC 1157 - generic-trap definitions

   COLD_START                  => 0,  # coldStart(0)
   WARM_START                  => 1,  # warmStart(1)
   LINK_DOWN                   => 2,  # linkDown(2)
   LINK_UP                     => 3,  # linkUp(3)
   AUTHENTICATION_FAILURE      => 4,  # authenticationFailure(4)
   EGP_NEIGHBOR_LOSS           => 5,  # egpNeighborLoss(5)
   ENTERPRISE_SPECIFIC         => 6,  # enterpriseSpecific(6)

   ## RFC 3412 - msgFlags::=OCTET STRING

   MSG_FLAGS_NOAUTHNOPRIV   => 0x00,  # Means noAuthNoPriv
   MSG_FLAGS_AUTH           => 0x01,  # authFlag
   MSG_FLAGS_PRIV           => 0x02,  # privFlag
   MSG_FLAGS_REPORTABLE     => 0x04,  # reportableFlag
   MSG_FLAGS_MASK           => 0x07,

   ## RFC 3411 - SnmpSecurityLevel::=TEXTUAL-CONVENTION

   SECURITY_LEVEL_NOAUTHNOPRIV => 1,  # noAuthNoPriv
   SECURITY_LEVEL_AUTHNOPRIV   => 2,  # authNoPriv
   SECURITY_LEVEL_AUTHPRIV     => 3,  # authPriv

   ## RFC 3411 - SnmpSecurityModel::=TEXTUAL-CONVENTION

   SECURITY_MODEL_ANY          => 0,  # Reserved for 'any'
   SECURITY_MODEL_SNMPV1       => 1,  # Reserved for SNMPv1
   SECURITY_MODEL_SNMPV2C      => 2,  # Reserved for SNMPv2c
   SECURITY_MODEL_USM          => 3,  # User-Based Security Model (USM) 

   ## Translation masks

   TRANSLATE_NONE           => 0x00,  # Bit masks used to determine
   TRANSLATE_OCTET_STRING   => 0x01,  # if a specific ASN.1 type is
   TRANSLATE_NULL           => 0x02,  # translated into a "human
   TRANSLATE_TIMETICKS      => 0x04,  # readable" form.
   TRANSLATE_OPAQUE         => 0x08,
   TRANSLATE_NOSUCHOBJECT   => 0x10,
   TRANSLATE_NOSUCHINSTANCE => 0x20,
   TRANSLATE_ENDOFMIBVIEW   => 0x40,
   TRANSLATE_UNSIGNED       => 0x80,
   TRANSLATE_ALL            => 0xff,

   ## Truth values 

   TRUE                     => 0x01,
   FALSE                    => 0x00,
};

## Package variables

our $DEBUG = FALSE;                    # Debug flag
our $AUTOLOAD;                         # Used by the AUTOLOAD method

## Initialize the request-id/msgID.

our $ID = int rand((2**16) - 1) + ($^T & 0xff);

# [public methods] -----------------------------------------------------------

sub new {
   my ($class, %argv) = @_;

   # Create a new data structure for the object
   my $this = bless {
      '_buffer'      =>  q{},             # Serialized message buffer
      '_error'       =>  undef,           # Error message
      '_index'       =>  0,               # Buffer index
      '_leading_dot' =>  FALSE,           # Prepend leading dot on OIDs
      '_length'      =>  0,               # Buffer length
      '_security'    =>  undef,           # Security Model object
      '_translate'   =>  TRANSLATE_NONE,  # Translation mode
      '_transport'   =>  undef,           # Transport Layer object
      '_version'     =>  SNMP_VERSION_1,  # SNMP version
   }, $class;

   # Validate the passed arguments

   for (keys %argv) {

      if (/^-?callback$/i) {
         $this->callback($argv{$_});
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif (/^-?leadingdot$/i) {
         $this->leading_dot($argv{$_});
      } elsif (/^-?msgid$/i) {
         $this->msg_id($argv{$_});
      } elsif (/^-?requestid$/i) {
         $this->request_id($argv{$_});
      } elsif (/^-?security$/i) {
         $this->security($argv{$_});
      } elsif (/^-?translate$/i) {
         $this->translate($argv{$_});
      } elsif (/^-?transport$/i) {
         $this->transport($argv{$_});
      } elsif (/^-?version$/i) {
         $this->version($argv{$_});
      } else {
         $this->_error('The argument "%s" is unknown', $_);
      }

      if (defined $this->{_error}) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }

   }

   return wantarray ? ($this, q{}) : $this;
}

{
   my $prepare_methods = {
      INTEGER,            \&_prepare_integer,
      OCTET_STRING,       \&_prepare_octet_string,
      NULL,               \&_prepare_null,
      OBJECT_IDENTIFIER,  \&_prepare_object_identifier,
      SEQUENCE,           \&_prepare_sequence,
      IPADDRESS,          \&_prepare_ipaddress,
      COUNTER,            \&_prepare_counter,
      GAUGE,              \&_prepare_gauge,
      TIMETICKS,          \&_prepare_timeticks,
      OPAQUE,             \&_prepare_opaque,
      COUNTER64,          \&_prepare_counter64,
      NOSUCHOBJECT,       \&_prepare_nosuchobject,
      NOSUCHINSTANCE,     \&_prepare_nosuchinstance,
      ENDOFMIBVIEW,       \&_prepare_endofmibview,
      GET_REQUEST,        \&_prepare_get_request,
      GET_NEXT_REQUEST,   \&_prepare_get_next_request,
      GET_RESPONSE,       \&_prepare_get_response,
      SET_REQUEST,        \&_prepare_set_request,
      TRAP,               \&_prepare_trap,
      GET_BULK_REQUEST,   \&_prepare_get_bulk_request,
      INFORM_REQUEST,     \&_prepare_inform_request,
      SNMPV2_TRAP,        \&_prepare_v2_trap,
      REPORT,             \&_prepare_report
   };

   sub prepare {
#     my ($this, $type, $value) = @_;

      return $_[0]->_error() if defined $_[0]->{_error};

      if (!defined $_[1]) {
         return $_[0]->_error('The ASN.1 type is not defined');
      }

      if (!exists $prepare_methods->{$_[1]}) {
         return $_[0]->_error('The ASN.1 type "%s" is unknown', $_[1]);
      }

      return $_[0]->${\$prepare_methods->{$_[1]}}($_[2]);
   }
}

sub context_engine_id {
   my ($this, $engine_id) = @_;

   # RFC 3412 - contextEngineID::=OCTET STRING

   if (@_ == 2) {
      if (!defined $engine_id) {
         return $this->_error('The contextEngineID value is not defined');
      }
      $this->{_context_engine_id} = $engine_id;
   }

   if (exists $this->{_context_engine_id}) {
      return $this->{_context_engine_id} || q{};
   } elsif (defined $this->{_security}) {
      return $this->{_security}->engine_id() || q{};
   }

   return q{};
}

sub context_name {
   my ($this, $name) = @_;

   # RFC 3412 - contextName::=OCTET STRING

   if (@_ == 2) {
      if (!defined $name) {
         return $this->_error('The contextName value is not defined');
      }
      $this->{_context_name} = $name;
   }

   return exists($this->{_context_name}) ? $this->{_context_name} : q{};
}

sub msg_flags {
   my ($this, $flags) = @_;

   # RFC 3412 - msgFlags::=OCTET STRING (SIZE(1)) 

   # NOTE: The stored value is not an OCTET STRING.

   if (@_ == 2) {
      if (!defined $flags) {
         return $this->_error('The msgFlags value is not defined');
      }
      $this->{_msg_flags} = $flags;
   }

   if (exists $this->{_msg_flags}) {
      return $this->{_msg_flags};
   }

   return MSG_FLAGS_NOAUTHNOPRIV;
}

sub msg_id {
   my ($this, $msg_id) = @_;

   # RFC 3412 - msgID::=INTEGER (0..2147483647)

   if (@_ == 2) {
      if (!defined $msg_id) {
         return $this->_error('The msgID value is not defined');
      }
      if (($msg_id < 0) || ($msg_id > 2147483647)) {
         return $this->_error(
            'The msgId %d is out of range (0..2147483647)', $msg_id
         );
      }
      $this->{_msg_id} = $msg_id;
   }

   if (exists $this->{_msg_id}) {
      return $this->{_msg_id};
   } elsif (exists $this->{_request_id}) {
      return $this->{_request_id};
   }

   return 0;
}

sub msg_max_size {
   my ($this, $size) = @_;

   # RFC 3412 - msgMaxSize::=INTEGER (484..2147483647)

   if (@_ == 2) {
      if (!defined $size) {
         return $this->_error('The msgMaxSize value is not defined');
      }
      if (($size < 484) || ($size > 2147483647)) {
         return $this->_error(
            'The msgMaxSize %d is out of range (484..2147483647)', $size
         );
      }
      $this->{_msg_max_size} = $size;
   }

   return $this->{_msg_max_size} || 484;
}

sub msg_security_model {
   my ($this, $model) = @_;

   # RFC 3412 - msgSecurityModel::=INTEGER (1..2147483647)

   if (@_ == 2) {
      if (!defined $model) {
         return $this->_error('The msgSecurityModel value is not defined');
      }
      if (($model < 1) || ($model > 2147483647)) {
         return $this->_error(
            'The msgSecurityModel %d is out of range (1..2147483647)', $model
         );
      }
      $this->{_security_model} = $model;
   }

   if (exists $this->{_security_model}) {
      return $this->{_security_model};
   } elsif (defined $this->{_security}) {
      return $this->{_security}->security_model();
   } else {
      if ($this->{_version} == SNMP_VERSION_1) {
         return SECURITY_MODEL_SNMPV1;
      } elsif ($this->{_version} == SNMP_VERSION_2C) {
         return SECURITY_MODEL_SNMPV2C;
      } elsif ($this->{_version} == SNMP_VERSION_3) {
         return SECURITY_MODEL_USM;
      }
   }

   return SECURITY_MODEL_ANY;
}

sub request_id {
   my ($this, $request_id) = @_;

   # request-id::=INTEGER

   if (@_ == 2) {
      if (!defined $request_id) {
         return $this->_error('The request-id value is not defined');
      }
      $this->{_request_id} = $request_id;
   }

   return exists($this->{_request_id}) ? $this->{_request_id} : 0;
}

sub security_level {
   my ($this, $level) = @_;

   # RFC 3411 - SnmpSecurityLevel::=INTEGER { noAuthNoPriv(1), 
   #                                          authNoPriv(2),
   #                                          authPriv(3) }

   if (@_ == 2) {
      if (!defined $level) {
         return $this->_error('The securityLevel value is not defined');
      }
      if (($level < SECURITY_LEVEL_NOAUTHNOPRIV) ||
          ($level > SECURITY_LEVEL_AUTHPRIV))
      {
         return $this->_error(
            'The securityLevel %d is out of range (%d..%d)', $level,
            SECURITY_LEVEL_NOAUTHNOPRIV, SECURITY_LEVEL_AUTHPRIV
         );
      }
      $this->{_security_level} = $level;
   }

   if (exists $this->{_security_level}) {
      return $this->{_security_level};
   } elsif (defined $this->{_security}) {
      return $this->{_security}->security_level();
   }

   return SECURITY_LEVEL_NOAUTHNOPRIV;
}

sub security_name {
   my ($this, $name) = @_;

   if (@_ == 2) {
      if (!defined $name) {
         return $this->_error('The securityName value is not defined');
      }
      # No length checks due to no limits by RFC 1157 for community name.
      $this->{_security_name} = $name;
   }

   if (exists $this->{_security_name}) {
      return $this->{_security_name};
   } elsif (defined $this->{_security}) {
      return $this->{_security}->security_name();
   }

   return q{};
}

sub version {
   my ($this, $version) = @_;

   if (@_ == 2) {
      if (($version == SNMP_VERSION_1)  ||
          ($version == SNMP_VERSION_2C) ||
          ($version == SNMP_VERSION_3))
      {
         $this->{_version} = $version;
      } else {
         return $this->_error('The SNMP version %d is not supported', $version);
      }
   }

   return $this->{_version};
}

sub error_status {
   return 0; # noError(0) 
}

sub error_index {
   return 0;
}

sub var_bind_list {
   return undef;
}

sub var_bind_names {
   return [];
}

sub var_bind_types {
   return undef;
}

#
# Security Model accessor methods
#

sub security {
   my ($this, $security) = @_;

   if (@_ == 2) {
      if (defined $security) {
         $this->{_security} = $security;
      } else {
         $this->_error_clear();
         return $this->_error('The Security Model object is not defined');
      }
   }

   return $this->{_security};
}

#
# Transport Domain accessor methods
#

sub transport {
   my ($this, $transport) = @_;

   if (@_ == 2) {
      if (defined $transport) {
         $this->{_transport} = $transport;
      } else {
         $this->_error_clear();
         return $this->_error('The Transport Domain object is not defined');
      }
   }

   return $this->{_transport};
}

sub hostname {
   my ($this) = @_;

   if (defined $this->{_transport}) {
      return $this->{_transport}->dest_hostname();
   }

   return q{};
}

sub dstname {
   require Carp;
   Carp::croak(
      sprintf '%s::dstname() is obsolete, use hostname() instead', ref $_[0]
   );

   # Never get here.
   return shift->hostname(@_);
}

sub max_msg_size {
   my ($this, $size) = @_;

   if (!defined $this->{_transport}) {
      return 0;
   }

   if (@_ == 2) {
      $this->_error_clear();
      if (defined ($size = $this->{_transport}->max_msg_size($size))) {
         return $size;
      }
      return $this->_error($this->{_transport}->error());
   }

   return $this->{_transport}->max_msg_size();
}

sub retries {
   return defined($_[0]->{_transport}) ? $_[0]->{_transport}->retries() : 0;
}

sub timeout {
   return defined($_[0]->{_transport}) ? $_[0]->{_transport}->timeout() : 0;
}

sub send {
   my ($this) = @_;

   $this->_error_clear();

   if (!defined $this->{_transport}) {
      return $this->_error('The Transport Domain object is not defined');
   }

   DEBUG_INFO('transport address %s', $this->{_transport}->dest_taddress());
   $this->_buffer_dump();

   if (defined (my $bytes = $this->{_transport}->send($this->{_buffer}))) {
      return $bytes;
   }

   return $this->_error($this->{_transport}->error());
}

sub recv {
   my ($this) = @_;

   $this->_error_clear();

   if (!defined $this->{_transport}) {
      return $this->_error('The Transport Domain object is not defined');
   }

   my $name = $this->{_transport}->recv($this->{_buffer});

   if (defined $name) {
      $this->{_length} = CORE::length($this->{_buffer});
      DEBUG_INFO('transport address %s', $this->{_transport}->peer_taddress());
      $this->_buffer_dump();
      return $name;
   }

   return $this->_error($this->{_transport}->error());
}

#
# Data representation methods
#

sub translate
{
   return (@_ == 2) ? $_[0]->{_translate} = $_[1] : $_[0]->{_translate};
}

sub leading_dot
{
   return (@_ == 2) ? $_[0]->{_leading_dot} = $_[1] : $_[0]->{_leading_dot};
}

#
# Callback handler methods
#

sub callback
{
   my ($this, $callback) = @_;

   if (@_ == 2) {
      if (ref($callback) eq 'CODE') {
         $this->{_callback} = $callback;
      } elsif (!defined $callback) {
         $this->{_callback} = undef;
      } else {
         DEBUG_INFO('unexpected callback format');
      }
   }

   return $this->{_callback};
}

sub callback_execute
{
   my ($this) = @_;

   if (!defined $this->{_callback}) {
      DEBUG_INFO('no callback');
      return TRUE;
   }

   # Protect ourselves from user error.
   eval { $this->{_callback}->($this); };

   # We clear the callback in case it was a closure which might hold
   # up the reference count of the calling object. 

   $this->{_callback} = undef;

   return ($@) ? $this->_error($@) : TRUE;
}

sub status_information
{
   my $this = shift;

   if (@_) {
      $this->{_error} = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0];
      if ($this->debug()) {
         printf "error: [%d] %s(): %s\n",
                (caller 0)[2], (caller 1)[3], $this->{_error};
      }
      $this->callback_execute();
   }

   return $this->{_error} || q{};
}

sub process_response_pdu
{
   goto &callback_execute;
}

sub timeout_id
{
   return (@_ == 2) ? $_[0]->{_timeout_id} = $_[1] : $_[0]->{_timeout_id};
}

#
# Buffer manipulation methods
#

#sub index

sub length
{
   return $_[0]->{_length};
}

sub prepend
{
   goto &_buffer_put;
}

sub append
{
   goto &_buffer_append;
}

sub copy
{
   return $_[0]->{_buffer};
}

sub reference
{
   return \$_[0]->{_buffer};
}

sub clear
{
   my ($this) = @_;

   $this->{_index}  = 0;
   $this->{_length} = 0;

   return substr $this->{_buffer}, 0, CORE::length($this->{_buffer}), q{};
}

sub dump
{
   goto &_buffer_dump;
}

#
# Debug/error handling methods
#

sub error
{
   my $this = shift;

   if (@_) {
      if (defined $_[0]) {
         $this->{_error} = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0];
         if ($this->debug()) {
            printf "error: [%d] %s(): %s\n",
                (caller 0)[2], (caller 1)[3], $this->{_error};
         }
      } else {
         $this->{_error} = undef;
      }
   }

   return $this->{_error} || q{};
}

sub debug
{
   return (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

sub AUTOLOAD
{
   my ($this) = @_;

   return if $AUTOLOAD =~ /::DESTROY$/;

   $AUTOLOAD =~ s/.*://;

   if (ref $this) {
      $this->_error_clear();
      return $this->_error('The method "%s" is not supported', $AUTOLOAD);
   } else {
      require Carp;
      Carp::croak(sprintf 'The function "%s" is not supported', $AUTOLOAD);
   }

   # Never get here.
   return;
}

# [private methods] ----------------------------------------------------------

#
# Basic Encoding Rules (BER) prepare methods
#

sub _prepare_type_length
{
#  my ($this, $type, $value) = @_;

   if (!defined $_[1]) {
      return $_[0]->_error('The ASN.1 type is not defined');
   }

   my $length = CORE::length($_[2]);

   if ($length < 0x80) {
      return $_[0]->_buffer_put(pack('C2', $_[1], $length) . $_[2]);
   } elsif ($length <= 0xff) {
      return $_[0]->_buffer_put(pack('C3', $_[1], 0x81, $length) . $_[2]);
   } elsif ($length <= 0xffff) {
      return $_[0]->_buffer_put(pack('CCn', $_[1], 0x82, $length) . $_[2]);
   }

   return $_[0]->_error('Unable to prepare the ASN.1 length');
}

sub _prepare_integer
{
   my ($this, $value) = @_;

   if (!defined $value) {
      return $this->_error('The INTEGER value is not defined');
   }

   if ($value !~ /^-?\d+$/) {
      return $this->_error(
         'The INTEGER value "%s" is expected in numeric format', $value
      );
   }

   if ($value < -2147483648 || $value > 4294967295) {
      return $this->_error(
         'The INTEGER value "%s" is out of range (-2147483648..4294967295)',
         $value
      );
   }

   return $this->_prepare_integer32(INTEGER, $value);
}

sub _prepare_unsigned32
{
   my ($this, $type, $value) = @_;

   if (!defined $value) {
      return $this->_error('The %s value is not defined', asn1_itoa($type));
   }

   if ($value !~ /^\d+$/) {
      return $this->_error(
         'The %s value "%s" is expected in positive numeric format',
         asn1_itoa($type), $value
      );
   }

   if ($value < 0 || $value > 4294967295) {
      return $this->_error(
         'The %s value "%s" is out of range (0..4294967295)',
         asn1_itoa($type), $value
      );
   }

   return $this->_prepare_integer32($type, $value);
}

sub _prepare_integer32
{
   my ($this, $type, $value) = @_;

   # Determine if the value is positive or negative
   my $negative = ($value < 0);

   # Check to see if the most significant bit is set, if it is we
   # need to prefix the encoding with a zero byte.

   my $size   = 4;     # Assuming 4 byte integers
   my $prefix = FALSE;
   my $bytes  = q{};

   if ((($value & 0xff000000) & 0x80000000) && (!$negative)) {
      $size++;
      $prefix = TRUE;
   }

   # Remove occurances of nine consecutive ones (if negative) or zeros
   # from the most significant end of the two's complement integer.

   while ((((!($value & 0xff800000))) ||
           ((($value & 0xff800000) == 0xff800000) && ($negative))) &&
           ($size > 1))
   {
      $size--;
      $value <<= 8;
   }

   # Add a zero byte so the integer is decoded as a positive value
   if ($prefix) {
      $bytes = pack 'x';
      $size--;
   }

   # Build the integer
   while ($size-- > 0) {
      $bytes .= pack 'C*', (($value & 0xff000000) >> 24);
      $value <<= 8;
   }

   # Encode ASN.1 header
   return $this->_prepare_type_length($type, $bytes);
}

sub _prepare_octet_string
{
   my ($this, $value) = @_;

   if (!defined $value) {
      return $this->_error('The OCTET STRING value is not defined');
   }

   return $this->_prepare_type_length(OCTET_STRING, $value);
}

sub _prepare_null
{
   return $_[0]->_prepare_type_length(NULL, q{});
}

sub _prepare_object_identifier
{
   my ($this, $value) = @_;

   if (!defined $value) {
      return $this->_error('The OBJECT IDENTIFIER value not defined');
   }

   # The OBJECT IDENTIFIER is expected in dotted notation.
   if ($value !~ m/^\.?\d+(?:\.\d+)* *$/) {
      return $this->_error(
         'The OBJECT IDENTIFIER value "%s" is expected in dotted decimal ' .
         'notation', $value
      );
   }

   # Break it up into sub-identifiers.
   my @subids = split /\./, $value;

   # If there was a leading dot on _any_ OBJECT IDENTIFIER passed to
   # a prepare method, return a leading dot on _all_ of the OBJECT
   # IDENTIFIERs in the process methods.

   if ($subids[0] eq q{}) {
      DEBUG_INFO('leading dot present');
      $this->{_leading_dot} = TRUE;
      shift @subids;
   }

   # RFC 2578 Section 3.5 - "...there are at most 128 sub-identifiers in
   # a value, and each sub-identifier has a maximum value of 2^32-1..."

   if (@subids > 128) {
      return $this->_error(
         'The OBJECT IDENTIFIER value "%s" contains more than the maximum ' .
         'of 128 sub-identifiers allowed', $value
      );
   }

   if (grep { $_ < 0 || $_ > 4294967295; } @subids) {
      return $this->_error(
         'The OBJECT IDENTIFIER value "%s" contains a sub-identifier which ' .
         'is out of range (0..4294967295)', $value
      );
   }

   # ISO/IEC 8825 - Specification of Basic Encoding Rules for Abstract
   # Syntax Notation One (ASN.1) dictates that the first two sub-identifiers
   # are encoded into the first identifier using the the equation:
   # subid = ((first * 40) + second).  Pad the OBJECT IDENTIFIER to at
   # least two sub-identifiers.

   while (@subids < 2) {
      push @subids, 0;
   }

   # The first sub-identifiers are limited to ccitt(0), iso(1), and
   # joint-iso-ccitt(2) as defined by RFC 2578.

   if ($subids[0] > 2) {
      return $this->_error(
         'The OBJECT IDENTIFIER value "%s" must begin with either 0 ' .
         '(ccitt), 1 (iso), or 2 (joint-iso-ccitt)', $value
      );
   }

   # If the first sub-identifier is 0 or 1, the second is limited to 0 - 39.

   if (($subids[0] < 2) && ($subids[1] >= 40)) {
      return $this->_error(
         'The second sub-identifier in the OBJECT IDENTIFIER value "%s" ' .
         'must be less than 40', $value
      );
   } elsif ($subids[1] >= (4294967295 - 80)) {
      return $this->_error(
         'The second sub-identifier in the OBJECT IDENTIFIER value "%s" ' .
         'must be less than %u', $value, (4294967295 - 80)
      );
   }

   # Now apply: subid = ((first * 40) + second)

   $subids[1] += (shift(@subids) * 40);

   # Encode each sub-identifier in base 128, most significant digit first,
   # with as few digits as possible.  Bit eight (the high bit) is set on
   # each byte except the last.

   # Encode the ASN.1 header
   return $this->_prepare_type_length(OBJECT_IDENTIFIER, pack 'w*', @subids);
}

sub _prepare_sequence
{
   return $_[0]->_prepare_implicit_sequence(SEQUENCE, $_[1]);
}

sub _prepare_implicit_sequence
{
   my ($this, $type, $value) = @_;

   if (defined $value) {
      return $this->_prepare_type_length($type, $value);
   }

   # If the passed value is undefined, we assume that the value of
   # the IMPLICIT SEQUENCE is the data currently in the serial buffer.

   if ($this->{_length} < 0x80) {
      return $this->_buffer_put(pack 'C2', $type, $this->{_length});
   } elsif ($this->{_length} <= 0xff) {
      return $this->_buffer_put(pack 'C3', $type, 0x81, $this->{_length});
   } elsif ($this->{_length} <= 0xffff) {
      return $this->_buffer_put(pack 'CCn', $type, 0x82, $this->{_length});
   }

   return $this->_error('Unable to prepare the ASN.1 SEQUENCE length');
}

sub _prepare_ipaddress
{
   my ($this, $value) = @_;

   if (!defined $value) {
      return $this->_error('IpAddress is not defined');
   }

   if ($value !~ /^\d+\.\d+\.\d+\.\d+$/) {
      return $this->_error(
         'The IpAddress value "%s" is expected in dotted decimal notation',
         $value
      );
   }

   my @octets = split /\./, $value;

   if (grep { $_ > 255; } @octets) {
      return $this->_error('The IpAddress value "%s" is invalid', $value);
   }

   return $this->_prepare_type_length(IPADDRESS, pack 'C4', @octets);
}

sub _prepare_counter
{
   return $_[0]->_prepare_unsigned32(COUNTER, $_[1]);
}

sub _prepare_gauge
{
   return $_[0]->_prepare_unsigned32(GAUGE, $_[1]);
}

sub _prepare_timeticks
{
   return $_[0]->_prepare_unsigned32(TIMETICKS, $_[1]);
}

sub _prepare_opaque
{
   my ($this, $value) = @_;

   if (!defined $value) {
      return $this->_error('The Opaque value is not defined');
   }

   return $this->_prepare_type_length(OPAQUE, $value);
}

sub _prepare_counter64
{
   my ($this, $value) = @_;

   # Validate the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The Counter64 type is not supported in SNMPv1');
   }

   # Validate the passed value
   if (!defined $value) {
      return $this->_error('The Counter64 value is not defined');
   }

   if ($value !~ /^\+?\d+$/) {
      return $this->_error(
         'The Counter64 value "%s" is expected in positive numeric format',
         $value
      );
   }

   $value = Math::BigInt->new($value);

   if ($value eq 'NaN') {
      return $this->_error('The Counter64 value "%s" is invalid', $value);
   }

   # Make sure the value is no more than 8 bytes long
   if ($value->bcmp('18446744073709551615') > 0) {
      return $this->_error(
          'The Counter64 value "%s" is out of range (0..18446744073709551615)',
          $value
      );
   }

   my ($quotient, $remainder, @bytes);

   # Handle a value of zero
   if ($value == 0) {
      unshift @bytes, 0x00;
   }

   while ($value > 0) {
      ($quotient, $remainder) = $value->bdiv(256);
      $value = Math::BigInt->new($quotient);
      unshift @bytes, $remainder;
   }

   # Make sure that the value is encoded as a positive value
   if ($bytes[0] & 0x80) {
      unshift @bytes, 0x00;
   }

   return $this->_prepare_type_length(COUNTER64, pack 'C*', @bytes);
}

sub _prepare_nosuchobject
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The noSuchObject type is not supported in SNMPv1');
   }

   return $this->_prepare_type_length(NOSUCHOBJECT, q{});
}

sub _prepare_nosuchinstance
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error(
         'The noSuchInstance type is not supported in SNMPv1'
      );
   }

   return $this->_prepare_type_length(NOSUCHINSTANCE, q{});
}

sub _prepare_endofmibview
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The endOfMibView type is not supported in SNMPv1');
   }

   return $this->_prepare_type_length(ENDOFMIBVIEW, q{});
}

sub _prepare_get_request
{
   return $_[0]->_prepare_implicit_sequence(GET_REQUEST, $_[1]);
}

sub _prepare_get_next_request
{
   return $_[0]->_prepare_implicit_sequence(GET_NEXT_REQUEST, $_[1]);
}

sub _prepare_get_response
{
   return $_[0]->_prepare_implicit_sequence(GET_RESPONSE, $_[1]);
}

sub _prepare_set_request
{
   return $_[0]->_prepare_implicit_sequence(SET_REQUEST, $_[1]);
}

sub _prepare_trap
{
   my ($this, $value) = @_;

   if ($this->{_version} != SNMP_VERSION_1) {
      return $this->_error('The Trap-PDU is only supported in SNMPv1');
   }

   return $this->_prepare_implicit_sequence(TRAP, $value);
}

sub _prepare_get_bulk_request
{
   my ($this, $value) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error(
         'The GetBulkRequest-PDU is not supported in SNMPv1'
      );
   }

   return $this->_prepare_implicit_sequence(GET_BULK_REQUEST, $value);
}

sub _prepare_inform_request
{
   my ($this, $value) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The InformRequest-PDU is not supported in SNMPv1');
   }

   return $this->_prepare_implicit_sequence(INFORM_REQUEST, $value);
}

sub _prepare_v2_trap
{
   my ($this, $value) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The SNMPv2-Trap-PDU is not supported in SNMPv1');
   }

   return $this->_prepare_implicit_sequence(SNMPV2_TRAP, $value);
}

sub _prepare_report
{
   my ($this, $value) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The Report-PDU is not supported in SNMPv1');
   }

   return $this->_prepare_implicit_sequence(REPORT, $value);
}

sub _process_null
{
   my ($this) = @_;

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   return $this->_error('NULL length is not equal to zero') if ($length != 0);

   if ($this->{_translate} & TRANSLATE_NULL) {
      DEBUG_INFO(q{translating NULL to 'NULL' string});
      return 'NULL';
   }

   return q{};
}

sub _process_nosuchobject
{
   my ($this) = @_;

   # Verify the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The noSuchObject type is not supported in SNMPv1');
   }

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   if ($length != 0) {
      return $this->_error('The noSuchObject length is not equal to zero');
   }

   if ($this->{_translate} & TRANSLATE_NOSUCHOBJECT) {
      DEBUG_INFO(q{translating noSuchObject to 'noSuchObject' string});
      return 'noSuchObject';
   }

   # XXX: Releases greater than v5.2.0 longer set the error-status.
   # $this->{_error_status} = NOSUCHOBJECT;

   return q{};
}

sub _process_nosuchinstance
{
   my ($this) = @_;

   # Verify the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error(
         'The noSuchInstance type is not supported in SNMPv1'
      );
   }

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   if ($length != 0) {
      return $this->_error('The noSuchInstance length is not equal to zero');
   }

   if ($this->{_translate} & TRANSLATE_NOSUCHINSTANCE) {
      DEBUG_INFO(q{translating noSuchInstance to 'noSuchInstance' string});
      return 'noSuchInstance';
   }

   # XXX: Releases greater than v5.2.0 longer set the error-status. 
   # $this->{_error_status} = NOSUCHINSTANCE;

   return q{};
}

sub _process_endofmibview
{
   my ($this) = @_;

   # Verify the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The endOfMibView type is not supported in SNMPv1');
   }

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   if ($length != 0) {
      return $this->_error('The endOfMibView length is not equal to zero');
   }

   if ($this->{_translate} & TRANSLATE_ENDOFMIBVIEW) {
      DEBUG_INFO(q{translating endOfMibView to 'endOfMibView' string});
      return 'endOfMibView';
   }

   # XXX: Releases greater than v5.2.0 longer set the error-status.
   # $this->{_error_status} = ENDOFMIBVIEW;

   return q{};
}

sub _process_pdu_type
{
   my ($this, $type) = @_;

   # Generic methods used to process the PDU type.  The ASN.1 type is
   # returned by the method as passed by the generic process routine.

   return defined($this->_process_length()) ? $type : $this->_error();
}

sub _process_get_request
{
   goto &_process_pdu_type;
}

sub _process_get_next_request
{
   goto &_process_pdu_type;
}

sub _process_get_response
{
   goto &_process_pdu_type;
}

sub _process_set_request
{
   goto &_process_pdu_type;
}

sub _process_trap
{
   my ($this) = @_;

   if ($this->{_version} != SNMP_VERSION_1) {
      return $this->_error('The Trap-PDU is only supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_get_bulk_request
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The GetBulkRequest-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_inform_request
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The InformRequest-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_v2_trap
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The SNMPv2-Trap-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_report
{
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The Report-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _prepare_var_bind_list
{
   my ($this, $var_bind) = @_;

   # The passed array is expected to consist of groups of four values
   # consisting of two sets of ASN.1 types and their values.

   if (@{$var_bind} % 4) {
      $this->var_bind_list(undef);
      return $this->_error(
         'The VarBind list size of %d is not a factor of 4', scalar @{$var_bind}
      );
   }

   # Initialize the "var_bind_*" data.

   $this->{_var_bind_list}  = {};
   $this->{_var_bind_names} = [];
   $this->{_var_bind_types} = {};

   # Use the object's buffer to build each VarBind SEQUENCE and then append
   # it to a local buffer.  The local buffer will then be used to create 
   # the VarBindList SEQUENCE.

   my ($buffer, $name_type, $name_value, $syntax_type, $syntax_value) = (q{});

   while (@{$var_bind}) {

      # Pull a quartet of ASN.1 types and values from the passed array.
      ($name_type, $name_value, $syntax_type, $syntax_value) =
         splice @{$var_bind}, 0, 4;

      # Reverse the order of the fields because prepare() does a prepend.

      # value::=ObjectSyntax
      if (!defined $this->prepare($syntax_type, $syntax_value)) {
         $this->var_bind_list(undef);
         return $this->_error();
      }

      # name::=ObjectName
      if ($name_type != OBJECT_IDENTIFIER) {
         $this->var_bind_list(undef);
         return $this->_error(
            'An ObjectName type of 0x%02x was expected, but 0x%02x was found',
            OBJECT_IDENTIFIER, $name_type
         );
      }
      if (!defined $this->prepare($name_type, $name_value)) {
         $this->var_bind_list(undef);
         return $this->_error();
      }

      # VarBind::=SEQUENCE
      if (!defined $this->prepare(SEQUENCE)) {
         $this->var_bind_list(undef);
         return $this->_error();
      }

      # Append the VarBind to the local buffer and clear it.
      $buffer .= $this->clear();

      # Populate the "var_bind_*" data so we can provide consistent
      # output for the methods regardless of whether we are a request 
      # or a response PDU.  Make sure the HASH key is unique if in 
      # case duplicate OBJECT IDENTIFIERs are provided.

      while (exists $this->{_var_bind_list}->{$name_value}) {
         $name_value .= q{ }; # Pad with spaces
      }

      $this->{_var_bind_list}->{$name_value}  = $syntax_value;
      $this->{_var_bind_types}->{$name_value} = $syntax_type;
      push @{$this->{_var_bind_names}}, $name_value;

   }

   # VarBindList::=SEQUENCE OF VarBind
   if (!defined $this->prepare(SEQUENCE, $buffer)) {
      $this->var_bind_list(undef);
      return $this->_error();
   }

   return TRUE;
}

#
# Abstract Syntax Notation One (ASN.1) utility functions
#

{
   my $types = {
      INTEGER,            'INTEGER',
      OCTET_STRING,       'OCTET STRING',
      NULL,               'NULL',
      OBJECT_IDENTIFIER,  'OBJECT IDENTIFIER',
      SEQUENCE,           'SEQUENCE',
      IPADDRESS,          'IpAddress',
      COUNTER,            'Counter',
      GAUGE,              'Gauge',
      TIMETICKS,          'TimeTicks',
      OPAQUE,             'Opaque',
      COUNTER64,          'Counter64',
      NOSUCHOBJECT,       'noSuchObject',
      NOSUCHINSTANCE,     'noSuchInstance',
      ENDOFMIBVIEW,       'endOfMibView',
      GET_REQUEST,        'GetRequest-PDU',
      GET_NEXT_REQUEST,   'GetNextRequest-PDU',
      GET_RESPONSE,       'GetResponse-PDU',
      SET_REQUEST,        'SetRequest-PDU',
      TRAP,               'Trap-PDU',
      GET_BULK_REQUEST,   'GetBulkRequest-PDU',
      INFORM_REQUEST,     'InformRequest-PDU',
      SNMPV2_TRAP,        'SNMPv2-Trap-PDU',
      REPORT,             'Report-PDU'
   };

   sub asn1_itoa
   {
      my ($type) = @_;

      return q{??} if (@_ != 1);

      if (!exists $types->{$type}) {
         return sprintf '?? [0x%02x]', $type;
      }

      return $types->{$type};
   }
}

sub asn1_ticks_to_time
{
   my $ticks = shift || 0;

   my $days = int($ticks / (24 * 60 * 60 * 100));
   $ticks %= (24 * 60 * 60 * 100);

   my $hours = int($ticks / (60 * 60 * 100));
   $ticks %= (60 * 60 * 100);

   my $minutes = int($ticks / (60 * 100));
   $ticks %= (60 * 100);

   my $seconds = ($ticks / 100);

   if ($days != 0){
      return sprintf '%d day%s, %02d:%02d:%05.02f', $days,
         ($days == 1 ? q{} : 's'), $hours, $minutes, $seconds;
   } elsif ($hours != 0) {
      return sprintf '%d hour%s, %02d:%05.02f', $hours,
         ($hours == 1 ? q{} : 's'), $minutes, $seconds;
   } elsif ($minutes != 0) {
      return sprintf '%d minute%s, %05.02f', $minutes,
         ($minutes == 1 ? q{} : 's'), $seconds;
   } else {
      return sprintf '%04.02f second%s', $seconds, ($seconds == 1 ? q{} : 's');
   }
}

#
# Error handlers
#

sub _error
{
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

sub _error_clear
{
   return $_[0]->{_error} = undef;
}

#
# Buffer manipulation methods
#

sub _buffer_put
{
#  my ($this, $value) = @_;

   return $_[0]->_error() if defined $_[0]->{_error};

   # Always reset the index when the buffer is modified
   $_[0]->{_index} = 0;

   # Update our length
   $_[0]->{_length} += CORE::length($_[1]);

   # Add the prefix to the current buffer
   substr $_[0]->{_buffer}, 0, 0, $_[1];

   return $_[0]->{_buffer};
}

sub _buffer_dump
{
   my ($this) = @_;

   return $DEBUG if (!$DEBUG);

   DEBUG_INFO('%d byte%s', $this->{_length}, $this->{_length} != 1 ? 's' : q{});

   my ($offset, $hex, $text) = (0, q{}, q{});

   while ($this->{_buffer} =~ /(.{1,16})/gs) {
      $hex  = unpack 'H*', ($text = $1);
      $hex .= q{ } x (32 - CORE::length($hex));
      $hex  = sprintf '%s %s %s %s  ' x 4, unpack 'a2' x 16, $hex;
      $text =~ s/[\x00-\x1f\x7f-\xff]/./g;
      printf "[%04d]  %s %s\n", $offset, uc($hex), $text;
      $offset += 16;
   }

   return $DEBUG;
}

sub DEBUG_INFO
{
   return $DEBUG if (!$DEBUG);

   return printf
      sprintf('debug: [%d] %s(): ', (caller 0)[2], (caller 1)[3]) .
      ((@_ > 1) ? shift(@_) : '%s') .
      "\n",
      @_;
}

1;
