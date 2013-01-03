package Net::SNMPu::Message;

# ABSTRACT: Object used to represent a SNMP message.

use sanity;
use bytes;

use Math::BigInt ();
use Convert::ASN1;
use Net::SNMPu::Constants ':ALL';  # LAZY

use Moo;
use MooX::Types::MooseLike::Base qw(InstanceOf ArrayRef Bool Str);
use MooX::Types::CLike qw(Nibble Octet Int32);

## Initialize the request-id/msgID.

our $ID = int rand((2**16) - 1) + ($^T & 0xff);

around BUILDARGS => sub {
   my ($orig, $self) = (shift, shift);
   my $hash = $self->_argument_munge(@_);
   $orig->($self, $hash);
};

sub BUILD {
   my $self = shift;
   return wantarray ? ($self, $self->error) : $self;
}

# [ASN1 definition] ------------------------------------------------------------------

my $ASN = Convert::ASN1->new(
   decode => {
      null => undef,
   }
);
$ASN->prepare(<<ASN) or die "Convert::ASN1->prepare ERROR: ", $ASN->error;
--######### Legend #########--
--   Original RFC comments like this
--## Our comments like this
--|  Disabled code (typically because Convert::ASN1 doesn't support it yet)

--## The end-all universal SNMP Message definition ##--

SNMPv123Message ::= CHOICE {
   snmpv12  Message,
   snmpv3   SNMPv3Message
}

--## Merging these definitions ##--

--| RFC1157-SNMP DEFINITIONS ::= BEGIN
--| COMMUNITY-BASED-SNMPv2 DEFINITIONS ::= BEGIN

-- top-level message

Message ::=
        SEQUENCE {
             version
                INTEGER, --| {
                --|     version-1(0),
                --|     version-2c(1)  -- modified from RFC 1157
                --| },

            community           -- community name
                OCTET STRING,

            data                -- PDUs as defined in [4]
                PDUs --| ANY
        }

--| END

--| SNMPv3MessageSyntax DEFINITIONS IMPLICIT TAGS ::= BEGIN

SNMPv3Message ::= SEQUENCE {
    -- identify the layout of the SNMPv3Message
    -- this element is in same position as in SNMPv1
    -- and SNMPv2c, allowing recognition
    -- the value 3 is used for snmpv3
    msgVersion INTEGER, --| ( 0 .. 2147483647 ),
    -- administrative parameters
    msgGlobalData HeaderData,
    -- security model-specific parameters
    -- format defined by Security Model
    msgSecurityParameters OCTET STRING,
    msgData  ScopedPduData
}

HeaderData ::= SEQUENCE {
    msgID      INTEGER, --| (0..2147483647),
    msgMaxSize INTEGER, --| (484..2147483647),

    msgFlags   OCTET STRING, --| (SIZE(1)),
               --  .... ...1   authFlag
               --  .... ..1.   privFlag
               --  .... .1..   reportableFlag
               --              Please observe:
               --  .... ..00   is OK, means noAuthNoPriv
               --  .... ..01   is OK, means authNoPriv
               --  .... ..10   reserved, must NOT be used.
               --  .... ..11   is OK, means authPriv

    msgSecurityModel INTEGER --| (1..2147483647)
}

ScopedPduData ::= CHOICE {
    plaintext    ScopedPDU,
    encryptedPDU OCTET STRING  -- encrypted scopedPDU value
}

ScopedPDU ::= SEQUENCE {
    contextEngineID  OCTET STRING,
    contextName      OCTET STRING,
    data             PDUs  --| ANY -- e.g., PDUs as defined in RFC 1905
}

--| END

--| SNMPv2-PDU DEFINITIONS ::= BEGIN

ObjectName ::= OBJECT IDENTIFIER

ObjectSyntax ::= CHOICE {
      simple           SimpleSyntax,
      application-wide ApplicationSyntax }

SimpleSyntax ::= CHOICE {
      integer-value   INTEGER, --| (-2147483648..2147483647),
      string-value    OCTET STRING, --| (SIZE (0..65535)),
      objectID-value  OBJECT IDENTIFIER }

ApplicationSyntax ::= CHOICE {
      ipAddress-value        IpAddress,
      counter-value          Counter32,
      timeticks-value        TimeTicks,
      arbitrary-value        Opaque,
      big-counter-value      Counter64,
      unsigned-integer-value Unsigned32 }


IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING -- (SIZE (4))

--## From RFC1155
NetworkAddress ::= IpAddress

Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER --| (0..4294967295)

Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER --| (0..4294967295)

Gauge32 ::= Unsigned32

TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER --| (0..4294967295)

Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING

Counter64 ::= [APPLICATION 6]
              IMPLICIT INTEGER --| (0..18446744073709551615)

-- protocol data units

PDUs ::= CHOICE {
     get-request      GetRequest-PDU,
     get-next-request GetNextRequest-PDU,
     get-bulk-request GetBulkRequest-PDU,
     response         Response-PDU,
     set-request      SetRequest-PDU,
     inform-request   InformRequest-PDU,
     trap             Trap-PDU,
     snmpV2-trap      SNMPv2-Trap-PDU,
     report           Report-PDU }

-- PDUs

GetRequest-PDU ::= [0] IMPLICIT PDU

GetNextRequest-PDU ::= [1] IMPLICIT PDU

Response-PDU ::= [2] IMPLICIT PDU

SetRequest-PDU ::= [3] IMPLICIT PDU

-- [4] is obsolete
--## We define it anyway...
Trap-PDU ::=
    [4]

         IMPLICIT SEQUENCE {
            enterprise          -- type of object generating
                                -- trap, see sysObjectID in [5]
                OBJECT IDENTIFIER,

            agent-addr          -- address of object generating
                NetworkAddress, -- trap

            generic-trap        -- generic trap type
                INTEGER, --| {
                --|     coldStart(0),
                --|     warmStart(1),
                --|     linkDown(2),
                --|     linkUp(3),
                --|     authenticationFailure(4),
                --|     egpNeighborLoss(5),
                --|     enterpriseSpecific(6)
                --| },

            specific-trap     -- specific code, present even
                INTEGER,      -- if generic-trap is not
                              -- enterpriseSpecific

            time-stamp        -- time elapsed between the last
              TimeTicks,      -- (re)initialization of the network
                              -- entity and the generation of the
                              -- trap

            variable-bindings   -- "interesting" information
                 VarBindList
         }

GetBulkRequest-PDU ::= [5] IMPLICIT BulkPDU

InformRequest-PDU ::= [6] IMPLICIT PDU

SNMPv2-Trap-PDU ::= [7] IMPLICIT PDU

--   Usage and precise semantics of Report-PDU are not defined
--   in this document.  Any SNMP administrative framework making
--   use of this PDU must define its usage and semantics.

Report-PDU ::= [8] IMPLICIT PDU

-- max-bindings INTEGER ::= 2147483647

PDU ::= SEQUENCE {
        request-id INTEGER, --| (-214783648..214783647),

        error-status                -- sometimes ignored
            INTEGER, --| {
            --|     noError(0),
            --|     tooBig(1),
            --|     noSuchName(2),      -- for proxy compatibility
            --|     badValue(3),        -- for proxy compatibility
            --|     readOnly(4),        -- for proxy compatibility
            --|     genErr(5),
            --|     noAccess(6),
            --|     wrongType(7),
            --|     wrongLength(8),
            --|     wrongEncoding(9),
            --|     wrongValue(10),
            --|     noCreation(11),
            --|     inconsistentValue(12),
            --|     resourceUnavailable(13),
            --|     commitFailed(14),
            --|     undoFailed(15),
            --|     authorizationError(16),
            --|     notWritable(17),
            --|     inconsistentName(18)
            --| },

        error-index                 -- sometimes ignored
            INTEGER, --| (0..max-bindings),

        variable-bindings           -- values are sometimes ignored
            VarBindList
    }

BulkPDU ::=                         -- must be identical in
    SEQUENCE {                      -- structure to PDU
        request-id      INTEGER, --| (-214783648..214783647),
        non-repeaters   INTEGER, --| (0..max-bindings),
        max-repetitions INTEGER, --| (0..max-bindings),

        variable-bindings           -- values are ignored
            VarBindList
    }

-- variable binding
VarBind ::= SEQUENCE {
        name ObjectName,

        CHOICE {
            value          ObjectSyntax,
            unSpecified    NULL,    -- in retrieval requests

                                    -- exceptions in responses
            noSuchObject   [0] IMPLICIT NULL,
            noSuchInstance [1] IMPLICIT NULL,
            endOfMibView   [2] IMPLICIT NULL
        }
    }

-- variable-binding list

VarBindList ::= SEQUENCE OF VarBind --| (SIZE (0..max-bindings)) OF VarBind

--| END

ASN

# ============================================================================

### FIXME: Rename this to "encode" ###
sub prepare {
   my ($self, $type, $value) = @_;

   state $prepare_macros = {
      INTEGER           => 'INTEGER',
      OCTET_STRING      => 'OCTET STRING',
      NULL              => 'NULL',
      OBJECT_IDENTIFIER => 'OBJECT IDENTIFIER',
      SEQUENCE          => 'SEQUENCE',
      IPADDRESS         => 'IpAddress',
      COUNTER           => 'Counter32',
      GAUGE             => 'Gauge32',
      TIMETICKS         => 'TimeTicks',
      OPAQUE            => 'Opaque',
      COUNTER64         => 'Counter64',
      NOSUCHOBJECT      => 'noSuchObject',
      NOSUCHINSTANCE    => 'noSuchInstance',
      ENDOFMIBVIEW      => 'endOfMibView',
      GET_REQUEST       => 'GetRequest-PDU',
      GET_NEXT_REQUEST  => 'GetNextRequest-PDU',
      GET_RESPONSE      => 'Response-PDU',
      SET_REQUEST       => 'SetRequest-PDU',
      TRAP              => 'Trap-PDU',
      GET_BULK_REQUEST  => 'GetBulkRequest-PDU',
      INFORM_REQUEST    => 'InformRequest-PDU',
      SNMPV2_TRAP       => 'SNMPv2-Trap-PDU',
      REPORT            => 'Report-PDU',
   };
   my $macro = $prepare_macros->{$type} || $type;

   # SNMP Version checks
   return $self->_error("$macro is only supported in SNMPv1")
      if ($self->version != SNMP_VERSION_1 && $macro eq 'Trap-PDU');
   return $self->_error("$macro is not supported in SNMPv1")
      if ($self->version == SNMP_VERSION_1 && $macro =~ /^(?:(?:GetBulk|Inform)Request|SNMPv2-Trap|Report)-PDU$|^(?:Counter64|noSuch(?:Object|Instance)|endOfMibView)$/);

   ### FIXME: Some of these might not be accessible ###
   my $msg_obj = $ASN->find($macro) // return $self->_error("Convert::ASN1->find: ".$ASN->error);

   # Some macros still need value munging, prior to passing to Convert::ASN1
   state $prepare_methods = {
      'OBJECT IDENTIFIER'  => \&_prepare_object_identifier,
      IpAddress            => \&_prepare_ipaddress,
      NetworkAddress       => \&_prepare_ipaddress,
      VarBindList          => \&_prepare_var_bind_list,
      'GetRequest-PDU'     => \&_prepare_pdu,
      'GetNextRequest-PDU' => \&_prepare_pdu,
      'Response-PDU'       => \&_prepare_pdu,
      'SetRequest-PDU'     => \&_prepare_pdu,
      'Trap-PDU'           => \&_prepare_trap_pdu,
      'GetBulkRequest-PDU' => \&_prepare_bulk_pdu,
      'InformRequest-PDU'  => \&_prepare_pdu,
      'SNMPv2-Trap-PDU'    => \&_prepare_pdu,
      'Report-PDU'         => \&_prepare_pdu,
   };
   my $method = $prepare_methods->{$macro};
   if (defined $method) {
      my $new = $self->$method($value, $macro);
      return unless defined $new;
      $value = $new;
   }

   return $msg_obj->encode($value) // $self->_error("Convert::ASN1->encode (via $macro): ".$ASN->error);
}

has session => (
   is        => 'ro',
   isa       => InstanceOf['Net::SNMPu'],
   predicate => 1,
   handles   => [qw(
      debug
      error
      security
      transport
      has_security
      has_transport
      _error
      _clear_error
      _argument_munge
   )],
);

sub DEBUG_INFO {
   return if ($_[0]->debug && DEBUG_MESSAGE);  # first for hot-ness
   shift;  # $self; not needed here

   return printf 'debug: [%d] %s(): '.(@_ > 1 ? shift : '%s')."\n", (
      (caller 0)[2],
      (caller 1)[3],
      @_
   );
}

# [attributes] ------------------------------------------------------------------

# RFC 3412 - contextEngineID::=OCTET STRING
has context_engine_id => (
   is        => 'rw',
   isa       => Str,
   lazy      => 1,
   default   => sub {
      my $self = shift;
      $self->has_security ? $self->security->engine_id : '';
   },
);

# RFC 3412 - contextName::=OCTET STRING
has context_name => (
   is        => 'rw',
   isa       => Str,
   predicate => 1,
);

# RFC 3412 - msgFlags::=OCTET STRING (SIZE(1))
# NOTE: The stored value is not an OCTET STRING.
has msg_flags => (
   is        => 'rw',
   isa       => Str,
   default   => sub { MSG_FLAGS_NOAUTHNOPRIV },
);

# RFC 3412 - msgID::=INTEGER (0..2147483647)
has msg_id => (
   is        => 'rw',
   isa       => Int32,  ### LAZY: Need to remove sign ###
   default   => sub { 0 },
);

# RFC 3412 - msgMaxSize::=INTEGER (484..2147483647)
has msg_max_size => (
   is        => 'rw',
   isa       => Int32,  ### LAZY: Need a better range ###
   default   => sub { 484 },
);

# RFC 3412 - msgSecurityModel::=INTEGER (1..2147483647)
has msg_security_model => (
   is        => 'rw',
   isa       => Int32,  ### LAZY: Need a better range ###
   lazy      => 1,
   default   => sub {
      my $self = shift;
      $self->has_security ? $self->security->security_model :
         ($self->version == SNMP_VERSION_1)  ? SECURITY_MODEL_SNMPV1  :
         ($self->version == SNMP_VERSION_2C) ? SECURITY_MODEL_SNMPV2C :
         ($self->version == SNMP_VERSION_3)  ? SECURITY_MODEL_USM     :
         SECURITY_MODEL_ANY;
   },
);

# RFC 3411 - SnmpSecurityLevel::=INTEGER { noAuthNoPriv(1),
#                                          authNoPriv(2),
#                                          authPriv(3) }
has security_level => (
   is        => 'rw',
   isa       => Nibble,  ### LAZY: Need a better range ###
   lazy      => 1,
   default   => sub {
      my $self = shift;
      $self->has_security ? $self->security->security_level : SECURITY_LEVEL_NOAUTHNOPRIV;
   },
);

has security_name => (
   is        => 'rw',
   isa       => Str,  # No length checks due to no limits by RFC 1157 for community name
   lazy      => 1,
   default   => sub {
      my $self = shift;
      $self->has_security ? $self->security->security_name : '';
   },
);

sub security_parameters {
   my $self = shift;
   $self->has_security ? $self->security->security_parameters : '';
}

# RFC 1157 - version INTEGER
# RFC 3412 - msgVersion INTEGER ( 0 .. 2147483647 )
has version => (
   is      => 'ro',
   isa     => Nibble,  # LAZY
   default => sub { SNMP_VERSION_1 },
);

# RFC 1157 - error-status INTEGER (currently up to 18)
has error_status => (
   is        => 'rw',
   isa       => Octet,  # LAZY
   default   => sub { 0 },  # noError(0)
);

# RFC 1157 - max-bindings INTEGER ::= 2147483647
# RFC 1157 - error-index INTEGER (0..max-bindings)
has error_index => (
   is        => 'rw',
   isa       => Int32,  # LAZY
   default   => sub { 0 },
);

# RFC 3416 - non-repeaters INTEGER (0..max-bindings)
has non_repeaters => (
   is        => 'rw',
   isa       => Int32,  # LAZY
   default   => sub { 0 },
);

# RFC 3416 - max-repetitions INTEGER (0..max-bindings)
has max_repetitions => (
   is        => 'rw',
   isa       => Int32,  # LAZY
   default   => sub { 0 },
);

has leading_dot => (
   is        => 'rw',
   isa       => Bool,
   default   => sub { FALSE },
);

has var_bind_list => (
   is        => 'rw',
   isa       => HashRef,
   predicate => 1,
   clearer   => 1,
);

has var_bind_names => (
   is        => 'rw',
   isa       => ArrayRef[Str],
   predicate => 1,
   clearer   => 1,
);

has var_bind_types => (
   is        => 'rw',
   isa       => HashRef,
   predicate => 1,
   clearer   => 1,
);

has pdu_type => (
   is        => 'rw',
   isa       => Octet,  # LAZY
   default   => sub { GET_REQUEST },
);

sub expect_response {
   my ($self) = @_;
   my $type = $self->pdu_type;

   return FALSE
      if ($type == GET_RESPONSE ||
          $type == TRAP         ||
          $type == SNMPV2_TRAP  ||
          $type == REPORT);

   return TRUE;
}

sub hostname {
   my $self = shift;
   $self->has_transport ? $self->transport->dest_hostname : '';
}

sub max_msg_size {
   my $self = shift;
   $self->has_transport ? $self->transport->max_msg_size(@_) : 0;
}

sub retries {
   my $self = shift;
   $self->has_transport ? $self->transport->retries : 0;
}

sub timeout {
   my $self = shift;
   $self->has_transport ? $self->transport->timeout : 0;
}

has timeout_id => (
   is  => 'rw',
   isa => ArrayRef,  ### FIXME: Confirm this... ###
);

# [public methods] ------------------------------------------------------------------

### FIXME ###
sub send {
   my ($self) = @_;

   $self->_clear_error;
   return $self->_error('The Transport Domain object is not defined') unless $self->has_transport;

   DEBUG_INFO('transport address %s', $self->transport->dest_taddress);
   $self->_buffer_dump;

   if (defined (my $bytes = $self->transport->send($self->_buffer))) {
      return $bytes;
   }

   return $self->_error($self->transport->error);
}

### FIXME ###
sub recv {
   my ($self) = @_;

   $self->_clear_error;
   return $self->_error('The Transport Domain object is not defined') unless $self->has_transport;

   my $name = $self->transport->recv($self->_buffer);

   if (defined $name) {
      ### FIXME: Figure out what to do with length ###
      $self->{_length} = CORE::length($self->_buffer);
      DEBUG_INFO('transport address %s', $self->transport->peer_taddress);
      $self->_buffer_dump;
      return $name;
   }

   return $self->_error($self->transport->error);
}

#
# Callback handler methods
#

### FIXME ###
sub callback {
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

### FIXME ###
sub callback_execute {
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

### FIXME ###
sub status_information {
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

### FIXME ###
sub process_response_pdu {
   goto &callback_execute;
}


#
# Buffer manipulation methods
#

### FIXME ###
sub index {
   my ($this, $index) = @_;

   if ((@_ == 2) && ($index >= 0) && ($index <= $this->{_length})) {
      $this->{_index} = $index;
   }

   return $this->{_index};
}

sub length {
   return $_[0]->{_length};
}

sub prepend {
   goto &_buffer_put;
}

sub append {
   goto &_buffer_append;
}

sub copy {
   return $_[0]->{_buffer};
}

sub reference {
   return \$_[0]->{_buffer};
}

sub clear {
   my ($this) = @_;

   $this->{_index}  = 0;
   $this->{_length} = 0;

   return substr $this->{_buffer}, 0, CORE::length($this->{_buffer}), q{};
}

sub dump {
   goto &_buffer_dump;
}

### FIXME: Rename this to "decode" ###
sub process {
#  my ($this, $expected, $found) = @_;

   state $process_methods = {
      INTEGER           => \&_process_integer,
      OCTET_STRING      => \&_process_octet_string,
      NULL              => \&_process_null,
      OBJECT_IDENTIFIER => \&_process_object_identifier,
      SEQUENCE          => \&_process_sequence,
      IPADDRESS         => \&_process_ipaddress,
      COUNTER           => \&_process_counter,
      GAUGE             => \&_process_gauge,
      TIMETICKS         => \&_process_timeticks,
      OPAQUE            => \&_process_opaque,
      COUNTER64         => \&_process_counter64,
      NOSUCHOBJECT      => \&_process_nosuchobject,
      NOSUCHINSTANCE    => \&_process_nosuchinstance,
      ENDOFMIBVIEW      => \&_process_endofmibview,
      GET_REQUEST       => \&_process_get_request,
      GET_NEXT_REQUEST  => \&_process_get_next_request,
      GET_RESPONSE      => \&_process_get_response,
      SET_REQUEST       => \&_process_set_request,
      TRAP              => \&_process_trap,
      GET_BULK_REQUEST  => \&_process_get_bulk_request,
      INFORM_REQUEST    => \&_process_inform_request,
      SNMPV2_TRAP       => \&_process_v2_trap,
      REPORT            => \&_process_report,
   };

   # XXX: If present, $found is updated as a side effect.

   return $_[0]->_error() if defined $_[0]->{_error};
   return $_[0]->_error() if !defined (my $type = $_[0]->_buffer_get(1));

   $type = unpack 'C', $type;

   if (!exists $process_methods->{$type}) {
      return $_[0]->_error('The ASN.1 type 0x%02x is unknown', $type);
   }

   # Check to see if a specific ASN.1 type was expected.
   if ((@_ > 1) && (defined $_[1]) && ($type != $_[1])) {
      return $_[0]->_error(
         'Expected %s, but found %s', asn1_itoa($_[1]), asn1_itoa($type)
      );
   }

   # Update the found ASN.1 type, if the argument is present.
   if (@_ == 3) {
      $_[2] = $type;
   }

   return $_[0]->${\$process_methods->{$type}}($type);
}

#
# OID Lex functions (previously stored in Net::SNMP)
#

sub oid_base_match {
   my ($this, $base, $oid) = @_;

   defined $oid  || return &FALSE;
   defined $base || return &FALSE;

   $base =~ s/^\.//o;
   $oid  =~ s/^\.//o;

   $base = pack 'N*', split m/\./, $base;
   $oid  = pack 'N*', split m/\./, $oid;

   return (substr($oid, 0, length $base) eq $base) ? &TRUE : &FALSE;
}

sub oid_lex_cmp {
   my ($this, $aa, $bb) = @_;

   for ($aa, $bb) {
      s/^\.//;
      s/ /\.0/g;
      $_ = pack 'N*', split m/\./;
   }

   return $aa cmp $bb;
}

sub oid_lex_sort {
   my $this = shift;
   if (@_ <= 1) {
      return @_;
   }

   return map  { $_->[0] }
          sort { $a->[1] cmp $b->[1] }
          map  {
             my $oid = $_;
             $oid =~ s/^\.//;
             $oid =~ s/ /\.0/g;
             [$_, pack('N*', split m/\./, $oid)]
          } @_;
}

# [private methods] ----------------------------------------------------------

### FIXME ###

# FYI, some of the safeguards from _prepare_* have been removed, since they
# aren't supported in Convert::ASN1 yet.  These include:
#
# * Range checks

### FIXME: encode_message_pdu needs to be called somehow... ###
sub encode_message_pdu {
   my ($self) = @_;

   state $asn_pdu_types = {
      GET_REQUEST       => 'get-request',
      GET_NEXT_REQUEST  => 'get-next-request',
      GET_RESPONSE      => 'response',
      SET_REQUEST       => 'set-request',
      TRAP              => 'trap',
      GET_BULK_REQUEST  => 'get-bulk-request',
      INFORM_REQUEST    => 'inform-request',
      SNMPV2_TRAP       => 'snmpV2-trap',
      REPORT            => 'report',
   };
   my $asn_type = $asn_pdu_types->{$self->pdu_type};

   # PDU
   my $data;
   if    ($self->pdu_type == TRAP) {
      # SNMPv1 Trap-PDU
      $data = {
         $asn_type, $self->prepare_trap
      };
   }
   elsif ($self->pdu_type == GET_BULK_REQUEST) {
      # GetBulkRequest-PDU
      $data = {
         $asn_type, {
            'request-id'        => $self->request_id,  ### FIXME: Needs randomization ###
            'error-status'      => 0,
            'error-index'       => 0,
            'variable-bindings' => $self->_prepare_var_bind_list,
         }
      };
   }
   else {
      # Everything else uses standard PDU
      $data = {
         $asn_type, {
            'request-id'        => $self->request_id,  ### FIXME: Needs randomization ###
            'non-repeaters'     => $self->non_repeaters,
            'max-repetitions'   => $self->max_repetitions,
            'variable-bindings' => $self->_prepare_var_bind_list,
         }
      };
   }

   my $msg;
   if ($self->version < SNMP_VERSION_3) {
      # SNMP v1/2c
      $msg = {
         snmpv12 => {
            version   => $self->version,
            community => $self->security_name,
            data      => $data,
         }
      };
   }
   else {
      # SNMP v3

      # msgFlags::=OCTET STRING
      my $security_level = $self->security_level;
      my $msg_flags      = MSG_FLAGS_NOAUTHNOPRIV | MSG_FLAGS_REPORTABLE;

      if ($security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {
         $msg_flags |= MSG_FLAGS_AUTH;
         if ($security_level > SECURITY_LEVEL_AUTHNOPRIV) {
            $msg_flags |= MSG_FLAGS_PRIV;
         }
      }
      $msg_flags &= ~MSG_FLAGS_REPORTABLE unless ($self->expect_response);
      $self->msg_flags($msg_flags);

      $msg = {
         snmpv3 => {
            msgVersion    => $self->version,
            msgGlobalData => {
               msgID                 => $self->msg_id,
               msgMaxSize            => $self->msg_max_size,
               msgFlags              => pack('C', $self->msg_flags),
               msgSecurityModel      => $self->msg_security_model,
               msgSecurityParameters => $self->security_parameters,  # verbosely defined in Security::USM
               msgData               => {
                  ($self->security_level > SECURITY_LEVEL_AUTHNOPRIV) ?
                     (encryptedPDU => $self->security->encrypt_pdu($data)) :  # security object is required here...
                     (plaintext => {
                        contextEngineID => $self->context_engine_id,
                        contextName     => $self->context_name,
                        data            => $data,
                     })
               }
            },
         }
      };
   }

   return $msg;
}

sub _prepare_object_identifier {
   my ($self, $value) = @_;

   return $self->_error('The OBJECT IDENTIFIER value not defined')
      unless defined $value;

   ### TODO: Add support for OID names ###

   # The OBJECT IDENTIFIER is expected in dotted notation.
   return $self->_error(
      'The OBJECT IDENTIFIER value "%s" is expected in dotted decimal ' .
      'notation', $value
   ) if ($value !~ m/^\.?\d+(?:\.\d+)* *$/);

   # Break it up into sub-identifiers.
   my @subids = split /\./, $value;

   # If there was a leading dot on _any_ OBJECT IDENTIFIER passed to
   # a prepare method, return a leading dot on _all_ of the OBJECT
   # IDENTIFIERs in the process methods.
   if ($subids[0] eq '') {
      DEBUG_INFO('leading dot present');
      $self->leading_dot(TRUE);
      shift @subids;
   }

   # RFC 2578 Section 3.5 - "...there are at most 128 sub-identifiers in
   # a value, and each sub-identifier has a maximum value of 2^32-1..."
   return $self->_error(
      'The OBJECT IDENTIFIER value "%s" contains more than the maximum ' .
      'of 128 sub-identifiers allowed', $value
   ) if (@subids > 128);

   return $self->_error(
      'The OBJECT IDENTIFIER value "%s" contains a sub-identifier which ' .
      'is out of range (0..4294967295)', $value
   ) if (grep { $_ < 0 || $_ > 4294967295 } @subids);

   # The first sub-identifiers are limited to ccitt(0), iso(1), and
   # joint-iso-ccitt(2) as defined by RFC 2578.
   return $self->_error(
      'The OBJECT IDENTIFIER value "%s" must begin with either 0 ' .
      '(ccitt), 1 (iso), or 2 (joint-iso-ccitt)', $value
   ) if (@subids && $subids[0] > 2);

   return join '.', @subids;
}

sub _prepare_ipaddress {
   my ($self, $value) = @_;

   return $self->_error('IpAddress is not defined')
      unless defined $value;

   return $self->_error(
      'The IpAddress value "%s" is expected in dotted decimal notation',
      $value
   ) if ($value !~ /^\d+\.\d+\.\d+\.\d+$/);

   my @octets = split /\./, $value;

   return $self->_error('The IpAddress value "%s" is invalid', $value)
      if (grep { $_ > 255 } @octets);

   return pack 'C4', @octets;
}

sub _prepare_var_bind_list {
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

sub _process_null {
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

sub _process_nosuchobject {
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

sub _process_nosuchinstance {
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

sub _process_endofmibview {
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

sub _process_pdu_type {
   my ($this, $type) = @_;

   # Generic methods used to process the PDU type.  The ASN.1 type is
   # returned by the method as passed by the generic process routine.

   return defined($this->_process_length()) ? $type : $this->_error();
}

sub _process_get_request {
   goto &_process_pdu_type;
}

sub _process_get_next_request {
   goto &_process_pdu_type;
}

sub _process_get_response {
   goto &_process_pdu_type;
}

sub _process_set_request {
   goto &_process_pdu_type;
}

sub _process_trap {
   my ($this) = @_;

   if ($this->{_version} != SNMP_VERSION_1) {
      return $this->_error('The Trap-PDU is only supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_get_bulk_request {
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The GetBulkRequest-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_inform_request {
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The InformRequest-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_v2_trap {
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The SNMPv2-Trap-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

sub _process_report {
   my ($this) = @_;

   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The Report-PDU is not supported in SNMPv1');
   }

   goto &_process_pdu_type;
}

#
# Abstract Syntax Notation One (ASN.1) utility functions
#
sub asn1_itoa {
   state $types = {
      INTEGER           => 'INTEGER',
      OCTET_STRING      => 'OCTET STRING',
      NULL              => 'NULL',
      OBJECT_IDENTIFIER => 'OBJECT IDENTIFIER',
      SEQUENCE          => 'SEQUENCE',
      IPADDRESS         => 'IpAddress',
      COUNTER           => 'Counter',
      GAUGE             => 'Gauge',
      TIMETICKS         => 'TimeTicks',
      OPAQUE            => 'Opaque',
      COUNTER64         => 'Counter64',
      NOSUCHOBJECT      => 'noSuchObject',
      NOSUCHINSTANCE    => 'noSuchInstance',
      ENDOFMIBVIEW      => 'endOfMibView',
      GET_REQUEST       => 'GetRequest-PDU',
      GET_NEXT_REQUEST  => 'GetNextRequest-PDU',
      GET_RESPONSE      => 'GetResponse-PDU',
      SET_REQUEST       => 'SetRequest-PDU',
      TRAP              => 'Trap-PDU',
      GET_BULK_REQUEST  => 'GetBulkRequest-PDU',
      INFORM_REQUEST    => 'InformRequest-PDU',
      SNMPV2_TRAP       => 'SNMPv2-Trap-PDU',
      REPORT            => 'Report-PDU',
   };

   my ($type) = @_;

   return q{??} if (@_ != 1);

   if (!exists $types->{$type}) {
      return sprintf '?? [0x%02x]', $type;
   }

   return $types->{$type};
}

### TODO: Switch to (Date)?Time::Duration ###
# (Or just remove...)
sub asn1_ticks_to_time {
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
# Buffer manipulation methods
#

sub _buffer_get {
   #my ($this, $requested) = @_;

   return $_[0]->_error() if defined $_[0]->{_error};

   # Return the number of bytes requested at the current index or
   # clear and return the whole buffer if no argument is passed.

   if (@_ == 2) {

      if (($_[0]->{_index} += $_[1]) > $_[0]->{_length}) {
         $_[0]->{_index} -= $_[1];
         if ($_[0]->{_length} >= $_[0]->max_msg_size()) {
            return $_[0]->_error(
               'The message size exceeded the buffer maxMsgSize of %d',
               $_[0]->max_msg_size()
            );
         }
         return $_[0]->_error('Unexpected end of message buffer');
      }

      return substr $_[0]->{_buffer}, $_[0]->{_index} - $_[1], $_[1];
   }

   # Always reset the index when the buffer is modified
   $_[0]->{_index} = 0;

   # Update our length to 0, the whole buffer is about to be cleared.
   $_[0]->{_length} = 0;

   ### HACK: Redefining length in the first place was kinda hacky... ###
   return substr $_[0]->{_buffer}, 0, CORE::length($_[0]->{_buffer}), q{};
}

sub _buffer_put {
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

sub _buffer_append {
   #my ($this, $value) = @_;

   return $_[0]->_error() if defined $_[0]->{_error};

   # Always reset the index when the buffer is modified
   $_[0]->{_index} = 0;

   # Update our length
   $_[0]->{_length} += CORE::length($_[1]);

   # Append to the current buffer
   return $_[0]->{_buffer} .= $_[1];
}

sub _buffer_dump {
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

1;
