package Net::SNMPu;

=head1 NAME

Net::SNMPu - Unified OO interface to SNMP

=head1 SYNOPSIS

   [FIXME: Insert code]

=head1 HISTORY

   [FIXME: Insert history]

=head1 DESCRIPTION

The Net::SNMPu module abstracts the intricate details of the Simple Network
Management Protocol by providing a high level programming interface to the
protocol.  Each Net::SNMPu object provides a one-to-one mapping between a Perl
object and a remote SNMP agent or manager.  Once an object is created, it can
be used to perform the basic protocol exchange actions defined by SNMP.

A Net::SNMPu object can be created such that it has either "blocking" or
"non-blocking" properties.  By default, the methods used to send SNMP messages
do not return until the protocol exchange has completed successfully or a
timeout period has expired. This behavior gives the object a "blocking"
property because the flow of the code is stopped until the method returns.

The optional named argument B<-nonblocking> can be passed to the object
constructor with a true value to give the object "non-blocking" behavior.
A method invoked by a non-blocking object queues the SNMP message and returns
immediately, allowing the flow of the code to continue. The queued SNMP
messages are not sent until an event loop is entered by calling the
C<snmp_dispatcher()> method.  When the SNMP messages are sent, any response to
the messages invokes the subroutine defined by the user when the message was
originally queued. The event loop exits when all messages have been removed
from the queue by either receiving a response, or by exceeding the number of
retries at the Transport Layer.

=head2 Blocking Objects

The default behavior of the methods associated with a Net::SNMPu object is to
block the code flow until the method completes.  For methods that initiate a
SNMP protocol exchange requiring a response, a hash reference containing the
results of the query is returned. The undefined value is returned by all
methods when a failure has occurred. The C<error> method can be used to
determine the cause of the failure.

The hash reference returned by a SNMP protocol exchange points to a hash
constructed from the VarBindList contained in the SNMP response message.  The
hash is created using the ObjectName and the ObjectSyntax pairs in the
VarBindList.  The keys of the hash consist of the OBJECT IDENTIFIERs in dotted
notation corresponding to each ObjectName in the VarBindList.  The value of
each hash entry is set equal to the value of the corresponding ObjectSyntax.
This hash reference can also be retrieved using the C<var_bind_list()> method.

=head2 Non-blocking Objects

When a Net::SNMPu object is created having non-blocking behavior, the invocation
of a method associated with the object returns immediately, allowing the flow
of the code to continue.  When a method is invoked that would initiate a SNMP
protocol exchange requiring a response, either a true value (i.e. 0x1) is
returned immediately or the undefined value is returned if there was a failure.
The C<error> method can be used to determine the cause of the failure.

The contents of the VarBindList contained in the SNMP response message can be
retrieved by calling the C<var_bind_list()> method using the object reference
passed as the first argument to the callback.  The value returned by the
C<var_bind_list()> method is a hash reference created using the ObjectName and
the ObjectSyntax pairs in the VarBindList.  The keys of the hash consist of
the OBJECT IDENTIFIERs in dotted notation corresponding to each ObjectName
in the VarBindList.  The value of each hash entry is set equal to the value of
the corresponding ObjectSyntax. The undefined value is returned if there has
been a failure and the C<error> method may be used to determine the reason.

=head2 Multiple Non-blocking Objects for Multiple Hosts

Multiple non-blocking sessions can be created to query multiple hosts at the
same time.  Each object is different and can have different options, but they
are all tied to the same dispatcher.  This means that the dispatcher will
process all requests from all hosts when the event loop is started, and won't
return until everything has replied or timed out.

The ancestor Net::SNMP code would send requests as fast as possible, even if the
transport buffers could not handle the amount of data returning back.  This was
especially true when communicating with multiple hosts on the traditional UDP
port.  Data was checked and processed as requests were being sent, but only one
packet at a time.

With the improved dispatcher code in Net::SNMPu, new requests are send to the
various hosts until data is detected on the transport buffers.  Then the data
is processed until the buffers are empty again.  This pattern is repeated until
the queue is empty.  This balance between sending and receiving keeps requests
flowing quickly, but mitigates against overloading.  This allows for dispatch
queues with as many requests and/or hosts as possible, as long as the Net::SNMPu
client has the CPU/RAM resources to process them.

See also L</max_requests>.

=cut

# ============================================================================

use sanity 0.94;
use Moo 1.000000;
use MooX::Types::MooseLike 0.15;  # ::Base got no $VERSION
use MooX::Types::MooseLike::Base qw(InstanceOf ArrayRef CodeRef Bool Str);
use MooX::Types::CLike qw(Nibble Byte);

use List::AllUtils 'first';

use Net::SNMPu::Dispatcher;
use Net::SNMPu::PDU;
use Net::SNMPu::Security;
use Net::SNMPu::Transport;
use Net::SNMPu::Message;
use Net::SNMPu::Constants qw( :ALL );  # LAZY

### FIXME ###
#our @EXPORT_OK = qw( oid_context_match );

=head1 METHODS

When named arguments are expected by the methods, three different styles are
supported.  All examples in this documentation use the standard lowercase
style:

   $object->method(argument  => $value);  # preferred
   $object->method(-argument => $value);
   $object->method(Argument  => $value);

The latter two forms are considered legacy usage and should not be used in
new code.

=cut

around BUILDARGS => sub {
   my ($orig, $self) = (shift, shift);
   my $hash = Net::SNMPu->_argument_munge(@_);

   my @trans_argv = (qw{
      hostname (?:de?st|peer)?(?:addr|port) (?:src|sock|local)(?:addr|port)
      maxrequests? maxmsgsize mtu retries timeout domain listen
   });
   my @sec_argv = (qw{
      community authoritative engine_id username
      (?:auth|priv)_(?:protocol|key|password)
   });

   # Pull out arguments associated with the Transport Domain.
   my $transport_argv = [];
   foreach my $key (keys %$hash) {
      foreach (@trans_argv) {
         if ($key =~ /^$_$/i) {
            push @$transport_argv, $key, delete $hash->{$key};
            last;
         }
      }
   }
   $hash->{_transport_argv} //= $transport_argv;

   # ...and ones associated with the Security Model.
   my $security_argv = [];
   foreach my $key (keys %$hash) {
      foreach (@sec_argv) {
         if ($key =~ /^$_$/i) {
            push @$security_argv, $key, delete $hash->{$key};
            last;
         }
      }
   }
   $hash->{_security_argv} //= $security_argv;

   $orig->($self, $hash);
};

=over

=item Non-blocking Objects Arguments

When a Net::SNMPu object has been created with a "non-blocking" property, most
methods that generate a SNMP message take additional arguments to support this
property.

=over

=item Callback

Most methods associated with a non-blocking object have an optional named
argument called B<-callback>.  The B<-callback> argument expects a reference
to a subroutine or to an array whose first element must be a reference to a
subroutine.  The subroutine defined by the B<-callback> option is executed when
a response to a SNMP message is received, an error condition has occurred, or
the number of retries for the message has been exceeded.

When the B<-callback> argument only contains a subroutine reference, the
subroutine is evaluated passing a reference to the original Net::SNMPu object
as the only parameter.  If the B<-callback> argument was defined as an array
reference, all elements in the array are passed to subroutine after the
reference to the Net::SNMPu object.  The first element, which is required to be
a reference to a subroutine, is removed before the remaining arguments are
passed to that subroutine.

Once one method is invoked with the B<-callback> argument, this argument stays
with the object and is used by any further calls to methods using the
B<-callback> option if the argument is absent.  The undefined value may be
passed to the B<-callback> argument to delete the callback.

B<NOTE:> The subroutine being passed with the B<-callback> named argument
should not cause blocking itself.  This will cause all the actions in the event
loop to be stopped, defeating the non-blocking property of the Net::SNMPu
module.

=item Delay

An optional argument B<-delay> can also be passed to non-blocking objects.  The
B<-delay> argument instructs the object to wait the number of seconds passed
to the argument before executing the SNMP protocol exchange.  The delay period
starts when the event loop is entered.  The B<-delay> parameter is applied to
all methods associated with the object once it is specified.  The delay value
must be set back to 0 seconds to disable the delay parameter.

=back

=item SNMPv3 Arguments

A SNMP context is a collection of management information accessible by a SNMP
entity.  An item of management information may exist in more than one context
and a SNMP entity potentially has access to many contexts.  The combination of
a contextEngineID and a contextName unambiguously identifies a context within
an administrative domain.  In a SNMPv3 message, the contextEngineID and
contextName are included as part of the scopedPDU.  All methods that generate
a SNMP message optionally take a B<-contextengineid> and B<-contextname>
argument to configure these fields.

=over

=item Context Engine ID

The B<-contextengineid> argument expects a hexadecimal string representing
the desired contextEngineID.  The string must be 10 to 64 characters (5 to
32 octets) long and can be prefixed with an optional "0x".  Once the
B<-contextengineid> is specified it stays with the object until it is changed
again or reset to default by passing in the undefined value.  By default, the
contextEngineID is set to match the authoritativeEngineID of the authoritative
SNMP engine.

=item Context Name

The contextName is passed as a string which must be 0 to 32 octets in length
using the B<-contextname> argument.  The contextName stays with the object
until it is changed.  The contextName defaults to an empty string which
represents the "default" context.

=back

=back

=cut

sub BUILD {
   my $self = shift;

   $self->security;  # force build of security model

   #unless ($self->_object_type_validate) {  ### FIXME ###

   return wantarray ? ($self, $self->error) : $self;
}

has dispatcher => (
   is       => 'ro',
   isa      => InstanceOf['Net::SNMPu::Dispatcher'],
   lazy      => 1,
   default  => sub {
      Net::SNMPu::Dispatcher->instance ||
      die 'FATAL: Failed to create Dispatcher instance';
   },
   init_arg => undef,
   handles  => {
      dispatch      => 'loop',
      dispatch_once => 'one_event',
   }
);

has pdu => (
   is        => 'rwp',
   isa       => InstanceOf['Net::SNMPu::PDU'],
   builder   => '_create_pdu',
   lazy      => 1,
   predicate => 1,
   init_arg  => undef,
   handles   => [qw(
      error_status
      error_index
      var_bind_list
      var_bind_names
      var_bind_types
   )],
);

has transport => (
   is        => 'rwp',
   isa       => InstanceOf['Net::SNMPu::Transport'],
   builder   => 'open',
   lazy      => 1,
   predicate => 1,
   init_arg  => undef,
   handles   => {qw(
      dest_hostname  hostname

      timeout        timeout
      retries        retries
      max_msg_size   max_msg_size
      max_requests   max_requests
   )},
);

has _transport_argv => (
   is       => 'ro',
   isa      => ArrayRef,
   required => 1,  # in BUILDARGS, anyway
);

has security => (
   is        => 'rw',
   isa       => InstanceOf['Net::SNMPu::Security'],
   lazy      => 1,
   predicate => 1,
   init_arg  => undef,
   default   => sub {
      my $self = shift;
      my ($security, $error) = Net::SNMPu::Security->new(@{ $self->_security_argv });
      if ($error) { $self->_error($error); return; }
      return $security;
   },
);

has _security_argv => (
   is       => 'ro',
   isa      => ArrayRef,
   required => 1,  # in BUILDARGS, anyway
);

has nonblocking => (
   is      => 'ro',
   isa     => Bool,
   default => sub { FALSE },
);

has context_engine_id => (
   is      => 'rw',
   isa     => sub {
      my $len = length $_[0];
      die "The contextEngineID length is out of range (5..32)"
         if ($len < 5 || $len > 32);
   },
   coerce  => sub {
      if ($_[0] =~ /^(?:0x)?([A-F0-9]+)$/i) {
         my $cei = pack 'H*', length($1) %  2 ? '0'.$1 : $1;
         my $len = length $cei;
         return $cei;
      }
   },
   trigger => sub {
      my ($self, $val, $oldval) = @_;

      $self->_clear_error;

      return $self->_error(
         'The contextEngineID argument is only supported in SNMPv3'
      ) if ($self->version != SNMP_VERSION_3);
   },
   predicate => 1,
);

has context_name => (
   is      => 'rw',
   isa     => sub {
      die 'The contextName length is out of range (0..32)'
         if (length($_[0]) <= 32);
   },
   trigger => sub {
      my ($self, $val, $oldval) = @_;

      $self->_clear_error;

      return $self->_error(
         'The contextName argument is only supported in SNMPv3'
      ) if ($self->version != SNMP_VERSION_3);
   },
   predicate => 1,
);

has delay => (
   is      => 'rw',
   isa     => sub {
      die 'The delay value "'.$_[0].'" is expected in positive numeric format'
         unless ($_[0] =~ /^\d+(?:\.\d+)?$/);
      die 'The delay value "'.$_[0].'" is out of range (0..31556926)'
         if ($_[0] < 0 || $_[0] > 31556926);
   },
   trigger => sub {
      my ($self, $val, $oldval) = @_;

      $self->_clear_error;

      return $self->_error(
         'The delay argument is not applicable to blocking objects'
      ) unless ($self->nonblocking);
   },
   default => sub { 0 },
);

### FIXME: Tie with transport builder ###
sub open {
   my ($self) = @_;

   # Clear any previous errors
   $self->_clear_error;

   # Create a Transport Domain object
   my ($transport, $error) = Net::SNMPu::Transport->new(
      @{ $self->_transport_argv },
      session => $self,
   );
   return if $self->has_error;

   # Perform SNMPv3 authoritative engine discovery.
   $self->_perform_discovery
      if ($self->version == SNMP_VERSION_3);

   return $self->_set_transport($transport);
}

=head2 session() - create a new Net::SNMPu object

   ($session, $error) = Net::SNMPu->session(
                           [-hostname      => $hostname,]
                           [-port          => $port,]
                           [-localaddr     => $localaddr,]
                           [-localport     => $localport,]
                           [-nonblocking   => $boolean,]
                           [-version       => $version,]
                           [-domain        => $domain,]
                           [-timeout       => $seconds,]
                           [-retries       => $count,]
                           [-maxmsgsize    => $octets,]
                           [-translate     => $translate,]
                           [-debug         => $bitmask,]
                           [-maxrequests   => $count,]       # non-blocking
                           [-community     => $community,]   # v1/v2c
                           [-username      => $username,]    # v3
                           [-authkey       => $authkey,]     # v3
                           [-authpassword  => $authpasswd,]  # v3
                           [-authprotocol  => $authproto,]   # v3
                           [-privkey       => $privkey,]     # v3
                           [-privpassword  => $privpasswd,]  # v3
                           [-privprotocol  => $privproto,]   # v3
                        );

This is the constructor for Net::SNMPu objects.  In scalar context, a
reference to a new Net::SNMPu object is returned if the creation of the object
is successful.  In list context, a reference to a new Net::SNMPu object and an
empty error message string is returned.  If a failure occurs, the object
reference is returned as the undefined value.  The error string may be used
to determine the cause of the error.

Most of the named arguments passed to the constructor define basic attributes
for the object and are not modifiable after the object has been created.  The
B<-timeout>, B<-retries>, B<-maxmsgsize>, B<-maxrequests>, B<-translate>, and
B<-debug> arguments are modifiable using an accessor method.  See their
corresponding method definitions for a complete description of their usage,
default values, and valid ranges.

=over

=item Transport Domain Arguments

The Net::SNMPu module uses UDP/IPv4 as the default Transport Domain to exchange
SNMP messages between the local and remote devices.  The module also supports
UDP/IPv6, TCP/IPv4, and TCP/IPv6 as alternative Transport Domains.  The
B<-domain> argument can be used to change the Transport Domain by setting the
value to one of the following strings: 'udp6', 'udp/ipv6'; 'tcp', 'tcp4',
'tcp/ipv4'; 'tcp6', or 'tcp/ipv6'.  The B<-domain> argument also accepts
the strings 'udp', 'udp4', or 'udp/ipv4' which correspond to the default
Transport Domain of UDP/IPv4.

The transport address of the destination SNMP device can be specified using
the B<-hostname> argument.  This argument is optional and defaults to
"localhost".  The destination port number can be specified as part of the
transport address or by using the B<-port> argument.  Either a numeric port
number or a textual service name can be specified.  A numeric port number in
parentheses can optionally follow the service name.  This port number will
be used if the service name cannot be resolved.  If the destination port number
is not specified, the well-known SNMP port number 161 is used.

By default the source transport address and port number are assigned
dynamically by the local device on which the Net::SNMPu module is being used.
This dynamic assignment can be overridden by using the B<-localaddr> and
B<-localport> arguments.  These arguments accept the same values as the
B<-hostname> and B<-port> arguments respectively.  The resolved address must
correspond to a valid address of an interface on the local device.

When using an IPv4 Transport Domain, the transport address can be specified
as either an IP network hostname or an IPv4 address in standard dotted notation.
The port information can be optionally appended to the hostname or address
delimited by a colon.  The accepted IPv4 transport address formats are
C<address>, C<address:port>, C<hostname>, and C<hostname:port>.

When using an IPv6 Transport Domain, the transport address can be specified
as an IP hostname (which will be looked up as a DNS quad-A record) or an IPv6
address in presentation format.  The port information can optionally be
included following a colon after the hostname or address.  When including this
information after an IPv6 address, the address must be enclosed in square
brackets.  The scope zone index (described in RFC 4007) can be specified after
the address as a decimal value delimited by a percent sign.  The accepted
transport address formats for IPv6 are C<address>, C<address%zone>,
C<[address]:port>, C<[address%zone]:port>, C<hostname>, and C<hostname:port>.

=item Security Model Arguments

The B<-version> argument controls which other arguments are expected or
required by the C<session()> constructor.  The Net::SNMPu module supports
SNMPv1, SNMPv2c, and SNMPv3.  The module defaults to SNMPv1 if no B<-version>
argument is specified.  The B<-version> argument expects either a digit (i.e.
'1', '2', or '3') or a string specifying the version (i.e. 'snmpv1',
'snmpv2c', or 'snmpv3') to define the SNMP version.

The Security Model used by the Net::SNMPu object is based on the SNMP version
associated with the object.  If the SNMP version is SNMPv1 or SNMPv2c a
Community-based Security Model will be used, while the User-based Security
Model (USM) will be used if the version is SNMPv3.

=over

=item Community-based Security Model Argument

If the Security Model is Community-based, the only argument available is the
B<-community> argument.  This argument expects a string that is to be used as
the SNMP community name.  By default the community name is set to 'public'
if the argument is not present.

=item User-based Security Model Arguments

The User-based Security Model (USM) used by SNMPv3 requires that a securityName
be specified using the B<-username> argument.  The creation of a Net::SNMPu
object with the version set to SNMPv3 will fail if the B<-username> argument
is not present.  The B<-username> argument expects a string 1 to 32 octets
in length.

Different levels of security are allowed by the User-based Security Model which
address authentication and privacy concerns.  A SNMPv3 Net::SNMPu object will
derive the security level (securityLevel) based on which of the following
arguments are specified.

By default a securityLevel of 'noAuthNoPriv' is assumed.  If the B<-authkey>
or B<-authpassword> arguments are specified, the securityLevel becomes
'authNoPriv'.  The B<-authpassword> argument expects a string which is at
least 1 octet in length.  Optionally, the B<-authkey> argument can be used so
that a plain text password does not have to be specified in a script.  The
B<-authkey> argument expects a hexadecimal string produced by localizing the
password with the authoritativeEngineID for the specific destination device.
The C<snmpkey> utility included with the distribution can be used to create
the hexadecimal string (see L<snmpkey>).

Two different hash algorithms are defined by SNMPv3 which can be used by the
Security Model for authentication.  These algorithms are HMAC-MD5-96 "MD5"
(RFC 1321) and HMAC-SHA-96 "SHA-1" (NIST FIPS PUB 180-1).   The default
algorithm used by the module is HMAC-MD5-96.  This behavior can be changed by
using the B<-authprotocol> argument.  This argument expects either the string
'md5' or 'sha' to be passed to modify the hash algorithm.

By specifying the arguments B<-privkey> or B<-privpassword> the securityLevel
associated with the object becomes 'authPriv'.  According to SNMPv3, privacy
requires the use of authentication.  Therefore, if either of these two
arguments are present and the B<-authkey> or B<-authpassword> arguments are
missing, the creation of the object fails.  The B<-privkey> and
B<-privpassword> arguments expect the same input as the B<-authkey> and
B<-authpassword> arguments respectively.

The User-based Security Model described in RFC 3414 defines a single encryption
protocol to be used for privacy.  This protocol, CBC-DES "DES" (NIST FIPS PUB
46-1), is used by default or if the string 'des' is passed to the
B<-privprotocol> argument.  The module also supports RFC 3826 which describes
the use of CFB128-AES-128 "AES" (NIST FIPS PUB 197) in the USM.  The AES
encryption protocol can be selected by passing 'aes' or 'aes128' to the
B<-privprotocol> argument.  By working with the Extended Security Options
Consortium L<http://www.snmp.com/protocol/eso.shtml>, the module also supports
CBC-3DES-EDE "Triple-DES" (NIST FIPS 46-3) in the User-based Security Model.
This is defined in the draft
L<http://www.snmp.com/eso/draft-reeder-snmpv3-usm-3desede-00.txt>.  The
Triple-DES encryption protocol can be selected using the B<-privprotocol>
argument with the string '3des' or '3desede'.

=back

=back

=cut

sub session {
   my $class = shift;

   my ($self, $error) = $class->new(@_);

   if (defined $self) {
      return wantarray ? (undef, $self->error) : undef
         unless (defined $self->open);
   }

   return wantarray ? ($self, $error) : $self;
}

=head2 close

Clear the Transport Domain associated with the object

   $session->close;

This method clears the Transport Domain and any errors associated with the
object.  Once closed, the Net::SNMPu object can no longer be used to send or
receive SNMP messages.

=cut

sub close {
   my ($self) = @_;

   $self->_clear_error;
   $self->_clear_pdu;
   $self->_clear_transport;
}

=head2 dispatch

Enter the non-blocking object event loop

   $session->dispatch;

This method enters the event loop associated with non-blocking Net::SNMPu
objects.  The method exits when all queued SNMP messages have received a
response or have timed out at the Transport Layer.

=head2 dispatch_once

Run a single dispatch event

   $session->dispatch_once;

This method runs a single dispatch "event".  What defines an event is kind
of "floaty", but it usually involves a single request send + some reads.

This typically isn't needed in order to run the dispatch queue in
non-blocking mode, but it has its advanced uses.  For example, this can be
used to run a separate loop in parallel without using the call stack.

=head2 get_request() - send a SNMP get-request to the remote agent

   $result = $session->get_request(
      # optional
      callback          => sub {},      # non-blocking
      delay             => $seconds,    # non-blocking
      context_engine_id => $engine_id,  # v3
      context_name      => $name,       # v3
      # required
      var_bind_list     => \@oids,
   );

This method performs a SNMP get-request query to gather data from the remote
agent on the host associated with the Net::SNMPu object.  The message is built
using the list of OBJECT IDENTIFIERs in dotted notation passed to the method
as an array reference using the B<-varbindlist> argument.  Each OBJECT
IDENTIFIER is placed into a single SNMP GetRequest-PDU in the same order that
it held in the original list.

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

=cut

sub get_request {
   my $self = shift;
   return $self->_prepare_request('get_request', [qw(
      callback
      delay
      context_engine_id
      context_name
      var_bind_list
   )], \@_);
}

=head2 get_next_request() - send a SNMP get-next-request to the remote agent

   $result = $session->get_next_request(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          -varbindlist      => \@oids,
                       );

This method performs a SNMP get-next-request query to gather data from the
remote agent on the host associated with the Net::SNMPu object.  The message
is built using the list of OBJECT IDENTIFIERs in dotted notation passed to the
method as an array reference using the B<-varbindlist> argument.  Each OBJECT
IDENTIFER is placed into a single SNMP GetNextRequest-PDU in the same order
that it held in the original list.

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

=cut

sub get_next_request {
   my $self = shift;
   return $self->_prepare_request('get_next_request', [qw(
      callback
      delay
      context_engine_id
      context_name
      var_bind_list
   )], \@_);
}

=head2 set_request() - send a SNMP set-request to the remote agent

   $result = $session->set_request(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          -varbindlist      => \@oid_value,
                       );

This method is used to modify data on the remote agent that is associated
with the Net::SNMPu object using a SNMP set-request.  The message is built
using a list of values consisting of groups of an OBJECT IDENTIFIER, an object
type, and the actual value to be set.  This list is passed to the method as
an array reference using the B<-varbindlist> argument.  The OBJECT IDENTIFIERs
in each trio are to be in dotted notation.  The object type is an octet
corresponding to the ASN.1 type of value that is to be set.  Each of the
supported ASN.1 types have been defined and are exported by the package by
default (see L<"EXPORTS">).

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

=cut

sub set_request {
   my $self = shift;
   return $self->_prepare_request('set_request', [qw(
      callback
      delay
      context_engine_id
      context_name
      var_bind_list
   )], \@_);
}

=head2 trap() - send a SNMP trap to the remote manager

   $result = $session->trap(
                          [-delay           => $seconds,]   # non-blocking
                          [-enterprise      => $oid,]
                          [-agentaddr       => $ipaddress,]
                          [-generictrap     => $generic,]
                          [-specifictrap    => $specific,]
                          [-timestamp       => $timeticks,]
                          -varbindlist      => \@oid_value,
                       );

This method sends a SNMP trap to the remote manager associated with the
Net::SNMPu object.  All arguments are optional and will be given the following
defaults in the absence of a corresponding named argument:

=over

=item *

The default value for the trap B<-enterprise> is "1.3.6.1.4.1", which
corresponds to "iso.org.dod.internet.private.enterprises".  The enterprise
value is expected to be an OBJECT IDENTIFER in dotted notation.

=item *

When the Transport Domain is UDP/IPv4 or TCP/IPv4, the default value for the
trap B<-agentaddr> is the IP address associated with the interface on which
the trap will be transmitted.  For other Transport Domains the B<-agentaddr>
is defaulted to "0.0.0.0".  When specified, the agent-addr is expected to be
an IpAddress in dotted notation.

=item *

The default value for the B<-generictrap> type is 6 which corresponds to
"enterpriseSpecific".  The generic-trap types are defined and can be exported
upon request (see L<"EXPORTS">).

=item *

The default value for the B<-specifictrap> type is 0.  No pre-defined values
are available for specific-trap types.

=item *

The default value for the trap B<-timestamp> is the "uptime" of the script.
The "uptime" of the script is the number of hundredths of seconds that have
elapsed since the script began running.  The time-stamp is expected to be a
TimeTicks number in hundredths of seconds.

=item *

The default value for the trap B<-varbindlist> is an empty array reference.
The variable-bindings are expected to be in an array format consisting of
groups of an OBJECT IDENTIFIER, an object type, and the actual value of the
object.  This is identical to the list expected by the C<set_request()> method.
The OBJECT IDENTIFIERs in each trio are to be in dotted notation.  The object
type is an octet corresponding to the ASN.1 type for the value. Each of the
supported types have been defined and are exported by default (see
L<"EXPORTS">).

=back

A true value is returned when the method is successful. The undefined value
is returned when a failure has occurred.  The C<error> method can be used to
determine the cause of the failure. Since there are no acknowledgements for
Trap-PDUs, there is no way to determine if the remote host actually received
the trap.

B<NOTE:> When the object is in non-blocking mode, the trap is not sent until
the event loop is entered and no callback is ever executed.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv1.

=cut

sub trap {
   my $self = shift;
   $self->_prepare_request('trap', [qw(
      delay
      enterprise
      agent_addr
      generic_trap
      specific_trap
      timestamp
      var_bind_list
   )], \@_);
   return $self->has_error ? undef : TRUE;
}

=head2 get_bulk_request() - send a SNMP get-bulk-request to the remote agent

   $result = $session->get_bulk_request(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          [-nonrepeaters    => $non_reps,]
                          [-maxrepetitions  => $max_reps,]
                          -varbindlist      => \@oids,
                       );

This method performs a SNMP get-bulk-request query to gather data from the
remote agent on the host associated with the Net::SNMPu object.  All arguments
are optional except B<-varbindlist> and will be given the following defaults
in the absence of a corresponding named argument:

=over

=item *

The default value for the get-bulk-request B<-nonrepeaters> is 0.  The
non-repeaters value specifies the number of variables in the
variable-bindings list for which a single successor is to be returned.

=item *

The default value for the get-bulk-request B<-maxrepetitions> is 0. The
max-repetitions value specifies the number of successors to be returned for
the remaining variables in the variable-bindings list.

=item *

The B<-varbindlist> argument expects an array reference consisting of a list of
OBJECT IDENTIFIERs in dotted notation.  Each OBJECT IDENTIFER is placed into a
single SNMP GetBulkRequest-PDU in the same order that it held in the original
list.

=back

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c or SNMPv3.

=cut

sub get_bulk_request {
   my $self = shift;
   return $self->_prepare_request('get_bulk_request', [qw(
      callback
      delay
      context_engine_id
      context_name
      non_repeaters
      max_repetitions
      var_bind_list
   )], \@_);
}

=head2 inform_request() - send a SNMP inform-request to the remote manager

   $result = $session->inform_request(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          -varbindlist      => \@oid_value,
                       );

This method is used to provide management information to the remote manager
associated with the Net::SNMPu object using an inform-request.  The message is
built using a list of values consisting of groups of an OBJECT IDENTIFIER,
an object type, and the actual value to be identified.  This list is passed
to the method as an array reference using the B<-varbindlist> argument.  The
OBJECT IDENTIFIERs in each trio are to be in dotted notation.  The object type
is an octet corresponding to the ASN.1 type of value that is to be identified.
Each of the supported ASN.1 types have been defined and are exported by the
package by default (see L<"EXPORTS">).

The first two variable-bindings fields in the inform-request are specified
by SNMPv2 and should be:

=over

=item *

sysUpTime.0 - ('1.3.6.1.2.1.1.3.0', TIMETICKS, $timeticks)

=item *

snmpTrapOID.0 - ('1.3.6.1.6.3.1.1.4.1.0', OBJECT_IDENTIFIER, $oid)

=back

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c or SNMPv3.

=cut

sub inform_request {
   my $self = shift;
   return $self->_prepare_request('inform_request', [qw(
      callback
      delay
      context_engine_id
      context_name
      var_bind_list
   )], \@_);
}

=head2 snmpv2_trap() - send a SNMP snmpV2-trap to the remote manager

   $result = $session->snmpv2_trap(
                          [-delay           => $seconds,]   # non-blocking
                          -varbindlist      => \@oid_value,
                       );

This method sends a snmpV2-trap to the remote manager associated with the
Net::SNMPu object.  The message is built using a list of values consisting of
groups of an OBJECT IDENTIFIER, an object type, and the actual value to be
identified.  This list is passed to the method as an array reference using the
B<-varbindlist> argument.  The OBJECT IDENTIFIERs in each trio are to be in
dotted notation.  The object type is an octet corresponding to the ASN.1 type
of value that is to be identified.  Each of the supported ASN.1 types have
been defined and are exported by the package by default (see L<"EXPORTS">).

The first two variable-bindings fields in the snmpV2-trap are specified by
SNMPv2 and should be:

=over

=item *

sysUpTime.0 - ('1.3.6.1.2.1.1.3.0', TIMETICKS, $timeticks)

=item *

snmpTrapOID.0 - ('1.3.6.1.6.3.1.1.4.1.0', OBJECT_IDENTIFIER, $oid)

=back

A true value is returned when the method is successful. The undefined value
is returned when a failure has occurred.  The C<error> method can be used
to determine the cause of the failure. Since there are no acknowledgements for
SNMPv2-Trap-PDUs, there is no way to determine if the remote host actually
received the snmpV2-trap.

B<NOTE:> When the object is in non-blocking mode, the snmpV2-trap is not sent
until the event loop is entered and no callback is ever executed.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c.  SNMPv2-Trap-PDUs are supported by SNMPv3, but require the sender of
the message to be an authoritative SNMP engine which is not currently supported
by the Net::SNMPu module.

=cut

sub snmpv2_trap {
   my $self = shift;
   return $self->_prepare_request('snmpv2_trap', [qw(
      delay
      context_engine_id
      context_name
      var_bind_list
   )], \@_);
}

=head2 get_table() - retrieve a table from the remote agent

   $result = $session->get_table(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          -baseoid          => $oid,
                          [-maxrepetitions  => $max_reps,]  # v2c/v3
                       );

This method performs repeated SNMP get-next-request or get-bulk-request
(when using SNMPv2c or SNMPv3) queries to gather data from the remote agent
on the host associated with the Net::SNMPu object.  The first message sent
is built using the OBJECT IDENTIFIER in dotted notation passed to the method
by the B<-baseoid> argument.   Repeated SNMP requests are issued until the
OBJECT IDENTIFIER in the response is no longer a child of the base OBJECT
IDENTIFIER.

The B<-maxrepetitions> argument can be used to specify the max-repetitions
value that is passed to the get-bulk-requests when using SNMPv2c or SNMPv3.
If this argument is not present, a value is calculated based on the maximum
message size for the Net::SNMPu object.  If the value is set to 1 or less,
get-next-requests will be used for the queries instead of get-bulk-requests.

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

B<WARNING:> Results from this method can become very large if the base
OBJECT IDENTIFIER is close to the root of the SNMP MIB tree.

=cut

### FIXME ###
sub get_table {
   my $self = shift;

   $self->_clear_error;

   my @argv;

   # Validate the passed arguments.

   unless (defined $self->_prepare_argv([qw( -callback
                                          -delay
                                          -contextengineid
                                          -contextname
                                          -baseoid
                                          -maxrepetitions  )], \@_, \@argv))
   {
      return $self->_error;
   }

   if ($argv[0] !~ m/^\.?\d+(?:\.\d+)* *$/) {
      return $self->_error(
         'The base OBJECT IDENTIFIER "%s" is expected in dotted decimal ' .
         'notation', $argv[0]
      );
   }

   # Create a new PDU.
   unless (defined $self->_create_pdu) {
      return $self->_error;
   }

   # Create table of values that need passed along with the
   # callbacks.  This just prevents a big argument list.

   my $argv = {
      base_oid   => $argv[0],
      callback   => $self->pdu->callback(),
      max_reps   => 5, # Also used as a limit for loop detection.
      repeat_cnt => 0,
      table      => undef,
      types      => undef,
      use_bulk   => FALSE
   };

   # Override the callback now that we have stored it.
   $self->pdu->callback(
      sub
      {
         $self->pdu = $_[0];
         $self->_clear_error;
         if ($self->pdu->error) {
            $self->_error($self->pdu->error);
         }
         $self->_get_table_cb($argv);
         return;
      }
   );

   # Determine if we are going to use get-next-requests or get-bulk-requests
   # based on the SNMP version and the -maxrepetitions argument.

   if ($self->version() == SNMP_VERSION_1) {
      if (defined $argv[1]) {
         return $self->_error(
            'The max-repetitions argument is not applicable when using SNMPv1'
         );
      }
   } else {
      unless (defined $argv[1]) {
         $argv->{use_bulk} = TRUE;
         $argv->{max_reps} = $self->max_msg_size;
      } elsif ($argv[1] > 1) {
         $argv->{use_bulk} = TRUE;
         $argv->{max_reps} = $argv[1];
      }
   }

   # Create either a get-next-request or get-bulk-request PDU.

   if ($argv->{use_bulk}) {
      unless (defined $self->pdu->prepare_get_bulk_request(0,
                                                           $argv->{max_reps},
                                                           [$argv[0]]))
      {
         return $self->_error($self->pdu->error);
      }
   } else {
      unless (defined $self->pdu->prepare_get_next_request([$argv[0]])) {
         return $self->_error($self->pdu->error);
      }
   }

   return $self->_send_pdu;
}

=head2 get_entries() - retrieve table entries from the remote agent

   $result = $session->get_entries(
                          [-callback        => sub {},]     # non-blocking
                          [-delay           => $seconds,]   # non-blocking
                          [-contextengineid => $engine_id,] # v3
                          [-contextname     => $name,]      # v3
                          -columns          => \@columns,
                          [-startindex      => $start,]
                          [-endindex        => $end,]
                          [-maxrepetitions  => $max_reps,]  # v2c/v3
                       );

This method performs repeated SNMP get-next-request or get-bulk-request
(when using SNMPv2c or SNMPv3) queries to gather data from the remote agent
on the host associated with the Net::SNMPu object.  Each message specifically
requests data for each OBJECT IDENTIFIER specified in the B<-columns> array.
The OBJECT IDENTIFIERs must correspond to column entries for a conceptual row
in a table.  They may however be columns in different tables as long as each
table is indexed the same way.  The optional B<-startindex> and B<-endindex>
arguments may be specified to limit the query to specific rows in the table(s).

The B<-startindex> can be specified as a single decimal value or in dotted
notation if the index associated with the entry so requires.  If the
B<-startindex> is specified, it will be include as part of the query results.
If no B<-startindex> is specified, the first request message will be sent
without an index.  To insure that the B<-startindex> is included, the last
sub-identifier in the index is decremented by one.  If the last sub-identifier
has a value of zero, the sub-identifier is removed from the index.

The optional B<-endindex> argument can be specified as a single decimal value
or in dotted notation.  If the B<-endindex> is specified, it will be included
as part of the query results.  If no B<-endindex> is specified, repeated SNMP
requests are issued until the response no longer returns entries matching
any of the columns specified in the B<-columns> array.

The B<-maxrepetitions> argument can be used to specify the max-repetitions
value that is passed to the get-bulk-requests when using SNMPv2c or SNMPv3.
If this argument is not present, a value is calculated based on the maximum
message size of the object and the number of columns specified in the
B<-columns> array.  If the value is set to 1 or less, get-next-requests will
be used for the queries instead of get-bulk-requests.

A reference to a hash is returned in blocking mode which contains the contents
of the VarBindList.  In non-blocking mode, a true value is returned when no
error has occurred.  In either mode, the undefined value is returned when an
error has occurred.  The C<error> method may be used to determine the cause
of the failure.

=cut

### FIXME ###
### FIXME: Support rowcallback ###

sub get_entries {
   my $self = shift;

   $self->_clear_error;

   my @argv;

   # Validate the passed arguments.

   unless (defined $self->_prepare_argv([qw( -callback
                                          -delay
                                          -contextengineid
                                          -contextname
                                          -columns
                                          -startindex
                                          -endindex
                                          -maxrepetitions
                                          -rowcallback     )], \@_, \@argv))
   {
      return $self->_error;
   }

   if (ref $argv[1] ne 'ARRAY') {
      return $self->_error('The columns argument expects an array reference');
   }

   unless (scalar @{$argv[1]}) {
      return $self->_error('An empty columns list was specified');
   }

   # Validate the column list.

   for (@{$argv[1]}) {
      unless (m/^\.?\d+(?:\.\d+)* *$/) {
         return $self->_error(
            'The columns list OBJECT IDENTIFIER "%s" is expected in dotted ' .
            'decimal notation', $_
         );
      }
   }

   my $start_index = undef;

   if (defined $argv[2]) {
      if ($argv[2] !~ m/^\d+(?:\.\d+)*$/) {
         return $self->_error(
            'The start index "%s" is expected in dotted decimal notation',
            $argv[2]
         );
      }
      my @subids = split m/\./, $argv[2];
      if ($subids[-1] > 0) {
         $subids[-1]--;
      } else {
         pop @subids;
      }
      $start_index = (@subids) ? join(q{.}, @subids) : q{};
   }

   if (defined $argv[3]) {
      if ($argv[3] !~ /^\d+(?:\.\d+)*$/) {
         return $self->_error(
             'The end index "%s" is expected in dotted decimal notation',
             $argv[3]
         );
      }
      if (defined $argv[2]) {
         if (oid_lex_cmp($argv[2], $argv[3]) > 0) {
            return $self->_error(
               'The end index cannot be less than the start index'
            );
         }
      }
   }

   # Undocumented and unsupported "-rowcallback" argument.

   if (defined $argv[5]) {
      if (ref $argv[5] eq 'CODE') {
         $argv[5] = [$argv[5]];
      } elsif ((ref($argv[5]) ne 'ARRAY') || (ref($argv[5]->[0]) ne 'CODE')) {
         return $self->_error('The syntax of the row callback is invalid');
      }
   }

   # Create a new PDU.
   unless (defined $self->_create_pdu) {
      return $self->_error;
   }

   # Create table of values that need passed along with the
   # callbacks.  This just prevents a big argument list.

   my $argv = {
      callback     => $self->pdu->callback(),
      columns      => $argv[1],
      end_index    => $argv[3],
      entries      => undef,
      last_index   => undef,
      max_reps     => 0,
      row_callback => $argv[5],
      start_index  => $argv[2],
      types        => undef,
      use_bulk     => FALSE
   };

   # Override the callback now that we have stored it.
   $self->pdu->callback(
      sub
      {
         $self->pdu = $_[0];
         $self->_clear_error;
         if ($self->pdu->error) {
            $self->_error($self->pdu->error);
         }
         $self->_get_entries_cb($argv);
         return;
      }
   );

   # Create the varBindList by indexing each column with the start index.
   my $vbl =
   [
      map {
         (defined $start_index) ? join q{.}, $_, $start_index : $_
      } @{$argv->{columns}}
   ];

   # Determine if we are going to use get-next-requests or get-bulk-requests
   # based on the SNMP version and the -maxrepetitions argument.

   if ($self->version() == SNMP_VERSION_1) {
      if (defined $argv[4]) {
         return $self->_error(
            'The max-repetitions argument is not applicable when using SNMPv1'
         );
      }
   } else {
      unless (defined $argv[4]) {
         $argv->{use_bulk} = TRUE;
         # Scale the max-repetitions based on the number of columns.
         $argv->{max_reps} =
            int($self->max_msg_size / @{$argv->{columns}}) + 1;
      } elsif ($argv[4] > 1) {
         $argv->{use_bulk} = TRUE;
         $argv->{max_reps} = $argv[4];
      }
   }

   # Create either a get-next-request or get-bulk-request PDU.

   if ($argv->{use_bulk}) {
      unless (defined $self->pdu->prepare_get_bulk_request(0,
                                                           $argv->{max_reps},
                                                           $vbl))
      {
         return $self->_error($self->pdu->error);
      }
   } else {
      unless (defined $self->pdu->prepare_get_next_request($vbl)) {
         return $self->_error($self->pdu->error);
      }
   }

   return $self->_send_pdu;
}

=head2 version

Get the SNMP version from the object

   $rfc_version = $session->version;

This method returns the current value for the SNMP version associated with
the object.  The returned value is the corresponding version number defined by
the RFCs for the protocol version field (i.e. SNMPv1 == 0, SNMPv2c == 1, and
SNMPv3 == 3).  The RFC versions are defined as constant by the module and can
be exported by request (see L<"EXPORTS">).

=cut

has version => (
   is      => 'ro',
   isa     => Nibble,  # LAZY
   coerce  => sub {
      state $versions = {
         '(?:snmp)?v?1'   => SNMP_VERSION_1,
         '(?:snmp)?v?2c?' => SNMP_VERSION_2C,
         '(?:snmp)?v?3'   => SNMP_VERSION_3,
      };

      for (keys %{$versions}) {
         if ($_[0] =~ m/^$_$/i) {
            return $versions->{$_};
         }
      }
   },
   default => sub { SNMP_VERSION_1 },
);

=head2 error

Get the current error message from the object

   $error_message = $session->error;

This method returns a text string explaining the reason for the last error.
An empty string is returned if no error has occurred.

=cut

has error => (
   is        => 'rwp',
   isa       => Str,
   default   => sub { '' },
   clearer   => '_clear_error',
   predicate => 1,
);

=head2 hostname

Get the hostname associated with the object

   $hostname = $session->hostname;

This method returns the parsed hostname string that is associated with the
object.  Any port information and formatting that can be included with the
corresponding C<session> constructor argument will be stripped and not
included as part of the returned string.

=cut

has hostname => (
   is      => 'ro',
   isa     => Str,
   default => sub { 'localhost' },
);

=head2 error_status

Get the current SNMP error-status from the object

   $error_status = $session->error_status;

This method returns the numeric value of the error-status contained in the
last SNMP message received by the object.

=head2 error_index

Get the current SNMP error-index from the object

   $error_index = $session->error_index;

This method returns the numeric value of the error-index contained in the
last SNMP message received by the object.

=head2 var_bind_list

Get the hash reference for the VarBindList values

   $values = $session->var_bind_list;

This method returns a hash reference created using the ObjectName and the
ObjectSyntax pairs in the VarBindList of the last SNMP message received by
the object.  The keys of the hash consist of the OBJECT IDENTIFIERs in dotted
notation corresponding to each ObjectName in the VarBindList.  If any of the
OBJECT IDENTIFIERs passed to the request method began with a leading dot, all
of the OBJECT IDENTIFIER hash keys will be prefixed with a leading dot.  If
duplicate OBJECT IDENTIFIERs are present in the VarBindList they will be
padded with spaces to make them an unique hash key.  The value of each hash
entry is set equal to the value of the corresponding ObjectSyntax.  The
undefined value is returned if there has been a failure.

=head2 var_bind_names

Get the array of the ObjectNames in the VarBindList

   @names = $session->var_bind_names;

This method returns an array containing the OBJECT IDENTIFIERs corresponding
to the ObjectNames in the VarBindList in the order that they were received
in the last SNMP message.  The entries in the array will map directly to the
keys in the hash reference returned by the methods that perform SNMP message
exchanges and by the C<var_bind_list()> and C<var_bind_types()> methods.  The
array returned for the convenience methods C<get_table()> and C<get_entries()>
will be in lexicographical order.  An empty array is returned if there has been
a failure.

=head2 var_bind_types

Get the hash reference for the VarBindList ASN.1 types

   $types = $session->var_bind_types;

This method returns a hash reference created using the ObjectName and the ASN.1
type of the ObjectSyntax in the VarBindList of the last SNMP message received
by the object.  The keys of the hash consist of the OBJECT IDENTIFIERs in
dotted notation corresponding to each ObjectName in the VarBindList.  The
value of each hash entry is set equal to the ASN.1 type of the corresponding
ObjectSyntax.  Constants for the supported ASN.1 types have been defined and
are exported by the package by default (see L<"EXPORTS">).  The undefined value
is returned if there has been a failure.

=head2 timeout

Set or get the current timeout period for the object

   $seconds = $session->timeout([$seconds]);

This method returns the current value for the Transport Layer timeout for
the Net::SNMPu object.  This value is the number of seconds that the object
will wait for a response from the agent on the remote host.  The default
timeout is 5.0 seconds.

If a parameter is specified, the timeout for the object is set to the provided
value if it falls within the range 1.0 to 60.0 seconds.  The undefined value
is returned upon an error and the C<error> method may be used to determine
the cause.

=head2 retries

Set or get the current retry count for the object

   $count = $session->retries([$count]);

This method returns the current value for the number of times to retry
sending a SNMP message to the remote host.  The default number of retries
is 1.

If a parameter is specified, the number of retries for the object is set to
the provided value if it falls within the range 0 to 20. The undefined value
is returned upon an error and the C<error> method may be used to determine
the cause.

=head2 max_msg_size

Set or get the current maxMsgSize for the object

   $octets = $session->max_msg_size([$octets]);

This method returns the current value for the maximum message size
(maxMsgSize) for the Net::SNMPu object.  This value is the largest message size
in octets that can be prepared or processed by the object.  The default
maxMsgSize is 1472 octets for UDP/IPv4, 1452 octets for UDP/IPv6, 1460 octets
for TCP/IPv4, and 1440 octets for TCP/IPv6.

If a parameter is specified, the maxMsgSize is set to the provided
value if it falls within the range 484 to 65535 octets.  The undefined
value is returned upon an error and the C<error> method may be used to
determine the cause.

B<NOTE:> When using SNMPv3, the maxMsgSize is actually contained in the SNMP
message (as msgMaxSize).  If the value received from a remote device is less
than the current maxMsgSize, the size is automatically adjusted to be the
lower value.

=head2 max_requests

Set or get the current number of maximum requests for the object

   $count = $session->max_requests([$count]);

This method returns the current value for the maximum number of new requests
for the Net::SNMPu object.  This only applies for non-blocking sessions, and is
individual for each session object (host).  The default is 3 new requests (per
host) at a time.

This argument is used to throttle the number of new requests sent to the host at
a time before it waits for other ones to finish.  For example, if it's set to the
default of three, and six "get_table" requests for that host are in the queue,
the dispatcher will only send the first three, wait for one of the requests to
finish, and send another one.  This will repeat until the queue is complete.

This is very useful for large requests with single or multiple hosts.  The ancestor
Net::SNMP code would send every request as fast as it could, which would
likely overload the host.  This would result in timeouts for all of the
requests.  With the throttle, requests can be controlled to what the host is
able to handle.  The default of 3 is good for most hosts, but can be set
lower or higher, depending on the speed and reliability of the host.

If a parameter is specified, the max requests is set to the provided
value if it falls within the range 0 to 65535.  The undefined value is returned
upon an error and the C<error> method may be used to determine the cause.

Setting it to 0 will remove any throttling, and a setting of 1 will only allow
a single request at a time for that session.  Any timeouts on the host will
automatically set this option to 1, to make retries more effective.  (If desired,
this behavior can be overridden by re-changing it on the callback sub.)

=head2 debug

Set or get the debug mode for the module

   $mask = $session->debug([$mask]);

This method is used to enable or disable debugging for the Net::SNMPu module.
Debugging can be enabled on a per component level as defined by a bit mask
passed to the C<debug> method.  The bit mask is broken up as follows:

=over

=item *

0x01 - Main Net::SNMPu functions

=item *

0x02 - Message or PDU encoding and decoding

=item *

0x04 - Transport Layer

=item *

0x08 - Dispatcher

=item *

0x10 - Message Processing

=item *

0x20 - Security

=back

Symbols representing these bit mask values are defined by the module and can
be exported using the I<:debug> tag (see L<"EXPORTS">).  If a non-numeric
value is passed to the C<debug()> method, it is evaluated in boolean context.
Debugging for all of the components is then enabled or disabled based on the
resulting truth value.

The current debugging mask is returned by the method.

=cut

has debug => (
   is      => 'rw',
   isa     => Byte,
   default => sub { DEBUG_NONE },
);

sub DEBUG_INFO {
   return if ($_[0]->debug & DEBUG_SNMP);  # first for hot-ness
   shift;  # $self; not needed here

   return printf 'debug: [%d] %s(): '.(@_ > 1 ? shift : '%s')."\n", (
      (caller 0)[2],
      (caller 1)[3],
      @_
   );
}

### FIXME: Move this ###

=head1 SUBROUTINES

=head2 oid_base_match() - determine if an OID has a specified OID base

   $value = oid_base_match($base_oid, $oid);

This function takes two OBJECT IDENTIFIERs in dotted notation and returns a
true value (i.e. 0x1) if the second OBJECT IDENTIFIER is equal to or is a
child of the first OBJECT IDENTIFIER in the SNMP Management Information Base
(MIB).  This function can be used in conjunction with the C<get-next-request()>
or C<get-bulk-request()> methods to determine when a OBJECT IDENTIFIER in the
GetResponse-PDU is no longer in the desired MIB tree branch.

=cut

sub oid_base_match { return Net::SNMPu::Message->oid_base_match(@_); }

=head2 oid_lex_cmp() - compare two OBJECT IDENTIFIERs lexicographically

   $cmp = oid_lex_cmp($oid1, $oid2);

This function takes two OBJECT IDENTIFIERs in dotted notation and returns one
of the values 1, 0, -1 if $oid1 is respectively lexicographically greater,
equal, or less than $oid2.

=cut

sub oid_lex_cmp { return Net::SNMPu::Message->oid_lex_cmp(@_); }

=head2 oid_lex_sort() - sort a list of OBJECT IDENTIFIERs lexicographically

   @sorted_oids = oid_lex_sort(@oids);

This function takes a list of OBJECT IDENTIFIERs in dotted notation and returns
the listed sorted in lexicographical order.

=cut

sub oid_lex_sort { return Net::SNMPu::Message->oid_lex_sort(@_); }

=head2 snmp_type_ntop() - convert an ASN.1 type to presentation format

   $text = snmp_type_ntop($type);

This function takes an ASN.1 type octet and returns a text string suitable for
presentation.  Some ASN.1 type definitions map to the same octet value when
encoded.  This method cannot distinguish between these multiple mappings and
the most basic type name will be returned.

=cut

sub snmp_type_ntop {
   goto &asn1_itoa;
}

=head2 ticks_to_time() - convert TimeTicks to formatted time

   $time = ticks_to_time($timeticks);

This function takes an ASN.1 TimeTicks value and returns a string representing
the time defined by the value.  The TimeTicks value is expected to be a
non-negative integer value representing the time in hundredths of a second
since some epoch.  The returned string will display the time in days, hours,
and seconds format according to the value of the TimeTicks argument.

=cut

sub ticks_to_time {
   goto &asn1_ticks_to_time;
}

# [private methods] ----------------------------------------------------------

sub _argument_munge {
   my ($self, @args) = @_;
   my $hash;

   if (@args == 1 && ref $args[0]) {
      for (ref $args[0]) {
         when ('ARRAY') { $hash = { @{$args[0]} }; }
         when ('HASH')  { $hash = { %{$args[0]} }; }
         default        { die "Invalid ref type for arguments!"; }
      }
   }
   else { $hash = { @args }; }

   foreach my $key (keys %$hash) {
      my $orig_key = $key;
      # -dashed_syntax
      $key =~ s/^\-//g;
      # CamelCase => camel_case
      $key =~ s/^([A-Z])/lc $1/ge;
      $key =~ s/(?!<_)([A-Z])/'_'.lc($1)/ge;
      $key =~ s/([A-Z])/lc $1/ge;

      $hash->{$key} = delete $hash->{$orig_key}
         unless ($orig_key eq $key);
   }

   return $hash;
}

sub _prepare_argv {
   my ($self, $allowed, $given) = @_;

   my $argv = $self->_argument_munge($given);
   my @methods = (qw/callback context_engine_id context_name delay/);

   # Go through the passed argument list and see if the argument is
   # allowed.  If it is, see if it applies to the object and has a
   # matching method call or add it the the new argv list to be
   # returned by this method.
   foreach my $key (keys %$argv) {
      return $self->_error('The argument "%s" is unknown', $key)
         unless (first { /^\Q$key\E$/i } @$allowed);
      $self->$key(delete $argv->{$key}) if ($key ~~ @methods);
   }

   return $argv;
}

sub _prepare_request {
   my ($self, $type, $allowed, $given) = @_;

   $self->_clear_error;

   # prep arguments
   my $argv = $self->_prepare_argv($allowed, $given);
   return if ($self->has_error);

   # create PDU
   $self->_create_pdu;
   return if ($self->has_error);

   # prepare PDU request
   my $prepare_method = 'prepare_'.$type;
   $self->pdu->$prepare_method($argv);
   return $self->_error($self->pdu->error) if ($self->pdu->has_error);

   return $self->_send_pdu;
}

### FIXME ###
sub _send_pdu {
   my ($self) = @_;

   # Check to see if we are still in the process of discovering the
   # authoritative SNMP engine.  If we are, queue the PDU if we are
   # running in non-blocking mode.

   if ($self->nonblocking && !$self->{_security}->discovered) {
      push @{$self->{_discovery_queue}}, [$self->pdu, $self->{_delay}];
      return TRUE;
   }

   # Hand the PDU off to the Dispatcher
   $self->dispatcher->send_pdu($self->pdu, $self->{_delay});

   # Activate the dispatcher if we are blocking
   unless ($self->nonblocking) {
      $self->dispatch;
   }

   # Return according to blocking mode
   return ($self->nonblocking) ? TRUE : $self->var_bind_list;
}

sub _create_pdu {
   my ($self) = @_;

   # Create the new PDU
   my ($pdu, $error) = Net::SNMPu::PDU->new(
      version    => $self->version,
      security   => $self->security,
      transport  => $self->transport,
      callback   => $self->_callback_closure,
      request_id => $self->dispatcher->msg_handle_alloc,
      ($self->has_context_engine_id ?
         (context_engine_id => $self->context_engine_id) : () ),
      ($self->has_context_name ?
         (context_name      => $self->context_name)      : () ),
   );

   return $self->_error($error) if $error;
   $self->_clear_error;

   # Return the PDU
   return $self->_set_pdu($pdu);
}

has callback => (
   is        => 'rw',
   isa       => ArrayRef,
   coerce  => sub {
      my ($callback) = @_;

      # We validate the callback argument and then create an anonymous
      # array where the first element is the subroutine reference and
      # the second element is an array reference containing arguments
      # to pass to the subroutine.
      my @argv;

      return unless defined $callback;

      if (ref $callback eq 'ARRAY' && ref $callback->[0] eq 'CODE') {
         ($callback, @argv) = @{$callback};
      }
      elsif (ref $callback ne 'CODE') {
         die 'The syntax of the callback is invalid';
      }

      return [$callback, \@argv];
   },
   trigger => sub {
      my ($self, $val, $oldval) = @_;

      $self->_clear_error;

      return $self->_error(
         'The callback argument is not applicable to blocking objects'
      ) if ($self->nonblocking);
   },
   clearer   => 1,
   predicate => 1,
);

sub _callback_closure {
   my ($self) = @_;

   # When a response message is received, the Dispatcher will create
   # a new PDU object and assign the callback to that object.  The
   # callback is then executed passing a reference to the PDU object
   # as the first argument.  We use a closure to assign that passed
   # reference to the Net:SNMPu object and then invoke the user defined
   # callback.

   unless ($self->nonblocking && $self->has_callback) {
      return [ sub {
         $self->pdu = $_[0];
         $self->_clear_error;
         $self->_error($self->pdu->error) if ($self->pdu->error);
         return;
      }, [] ];
   }

   my ($callback, $argv) = @{$self->callback};
   return [ sub {
      $self->pdu = $_[0];
      $self->_clear_error;
      $self->_error($self->pdu->error) if ($self->pdu->error);
      $callback->($self, @{$argv});
      return;
   }, [] ];
}

### FIXME: Need to check the dispatcher queue instead ###
my $NONBLOCKING = 0;
my $BLOCKING    = 0;

sub _object_type_validate {
   my ($self) = @_;

   # Since both non-blocking and blocking objects use the same
   # Dispatcher instance, allowing both objects types to exist at
   # the same time would cause problems.  This method is called
   # by the constructor to track the object counts based on the
   # non-blocking property and returns an error if the two types
   # would exist at the same time.

   my $count = ($self->nonblocking) ? ++$NONBLOCKING : ++$BLOCKING;

   if ($self->nonblocking && $BLOCKING) {
      return $self->_error(
         'Cannot create non-blocking objects when blocking objects exist'
      );
   } elsif (!$self->nonblocking && $NONBLOCKING) {
      return $self->_error(
         'Cannot create blocking objects when non-blocking objects exist'
      );
   }

   return TRUE;
}

### FIXME ###
sub _perform_discovery {
   my ($self) = @_;

   return TRUE if ($self->_security->discovered);

   # RFC 3414 - Section 4: "Discovery... ...may be accomplished by
   # generating a Request message with a securityLevel of noAuthNoPriv,
   # a msgUserName of zero-length, a msgAuthoritativeEngineID value of
   # zero length, and the varBindList left empty."

   # Create a new PDU
   unless (defined $self->_create_pdu) {
      return $self->_discovery_failed;
   }

   # Create the callback and assign it to the PDU
   $self->pdu->callback(
      sub
      {
         $self->pdu = $_[0];
         $self->_clear_error;
         if ($self->pdu->error) {
            $self->_error($self->pdu->error . ' during discovery');
         }
         $self->_discovery_engine_id_cb;
         return;
      }
   );

   # Prepare an empty get-request
   unless (defined $self->pdu->prepare_get_request) {
      $self->_error($self->pdu->error);
      return $self->_discovery_failed;
   }

   # Send the PDU (as a priority, so that we don't build up a
   # large discovery queue)
   $self->dispatcher->send_pdu_priority($self->pdu);

   unless ($self->nonblocking) {
      $self->dispatch;
   }

   return ($self->{_error}) ? $self->_error : TRUE;
}

### FIXME ###
sub _discovery_engine_id_cb {
   my ($self) = @_;

   # "The response to this message will be a Report message containing
   # the snmpEngineID of the authoritative SNMP engine...  ...with the
   # usmStatsUnknownEngineIDs counter in the varBindList."  If another
   # error is returned, we assume snmpEngineID discovery has failed.

   if ($self->{_error} !~ /usmStatsUnknownEngineIDs/) {
      return $self->_discovery_failed;
   }

   # Clear the usmStatsUnknownEngineIDs error
   $self->_clear_error;

   # If the security model indicates that discovery is complete,
   # we send any pending messages and return success.  If discovery
   # is not complete, we probably need to synchronize with the
   # remote authoritative engine.

   if ($self->{_security}->discovered) {
      $self->DEBUG_INFO('discovery complete');
      return $self->_discovery_complete;
   }

   # "If authenticated communication is required, then the discovery
   # process should also establish time synchronization with the
   # authoritative SNMP engine.  This may be accomplished by sending
   # an authenticated Request message..."

   # Create a new PDU
   unless (defined $self->_create_pdu) {
      return $self->_discovery_failed;
   }

   # Create the callback and assign it to the PDU
   $self->pdu->callback(
      sub
      {
         $self->pdu = $_[0];
         $self->_clear_error;
         if ($self->pdu->error) {
            $self->_error($self->pdu->error . ' during synchronization');
         }
         $self->_discovery_synchronization_cb;
         return;
      }
   );

   # Prepare an empty get-request
   unless (defined $self->pdu->prepare_get_request) {
      $self->_error($self->pdu->error);
      return $self->_discovery_failed;
   }

   # Send the (priority) PDU
   $self->dispatcher->send_pdu_priority($self->pdu);

   unless ($self->nonblocking) {
      $self->dispatch;
   }

   return ($self->{_error}) ? $self->_error : TRUE;
}

### FIXME ###
sub _discovery_synchronization_cb {
   my ($self) = @_;

   # "The response... ...will be a Report message containing the up
   # to date values of the authoritative SNMP engine's snmpEngineBoots
   # and snmpEngineTime...  It also contains the usmStatsNotInTimeWindows
   # counter in the varBindList..."  If another error is returned, we
   # assume that the synchronization has failed.

   if (($self->{_security}->discovered) &&
       ($self->{_error} =~ /usmStatsNotInTimeWindows/))
   {
      $self->_clear_error;
      $self->DEBUG_INFO('discovery and synchronization complete');
      return $self->_discovery_complete;
   }

   # If we received the usmStatsNotInTimeWindows report or no error, but
   # we are still not synchronized, provide a generic error message.

   if ((!$self->{_error}) || ($self->{_error} =~ /usmStatsNotInTimeWindows/)) {
      $self->_clear_error;
      $self->_error('Time synchronization failed during discovery');
   }

   $self->DEBUG_INFO('synchronization failed');

   return $self->_discovery_failed;
}

### FIXME ###
sub _discovery_failed {
   my ($self) = @_;

   # The discovery process has failed, clear the current PDU and the
   # Transport Domain so no one can use this object to send messages.

   $self->_clear_pdu;
   $self->_clear_transport;

   # Inform the command generator about the current error.
   while (my $q = shift @{$self->{_discovery_queue}}) {
      $q->[0]->status_information($self->{_error});
   }

   return $self->_error;
}

### FIXME ###
sub _discovery_complete {
   my ($self) = @_;

   # Discovery is complete, send any pending messages.
   while (my $q = shift @{$self->{_discovery_queue}}) {
      $self->dispatcher->send_pdu(@{$q});
   }

   return ($self->{_error}) ? $self->_error : TRUE;
}

### FIXME ###
sub _get_table_cb {
   my ($self, $argv) = @_;

   # Use get-next-requests or get-bulk-requests until the response is
   # not a subtree of the base OBJECT IDENTIFIER.  Return the table only
   # if there are no errors other than a noSuchName(2) error since the
   # table could be at the end of the tree.  Also return the table when
   # the value of the OID equals endOfMibView(2) when using SNMPv2c.

   # Get the current callback.
   my $callback = $self->pdu->callback;

   # Assign the user callback to the PDU.
   $self->pdu->callback($argv->{callback});

   my $list  = $self->var_bind_list;
   my $types = $self->var_bind_types;
   my @names = $self->var_bind_names;
   my $next  = undef;

   while (@names) {

      $next = shift @names;

      # Check to see if we are still in the correct subtree and have
      # not received a endOfMibView exception.

      unless (oid_base_match($argv->{base_oid}, $next) ||
          ($types->{$next} == ENDOFMIBVIEW))
      {
         $next = undef; # End of table.
         last;
      }

      # Add the entry to the table only if it is not already present
      # and check to make sure that the remote host does not respond
      # incorrectly causing the requests to loop forever.

      unless (exists $argv->{table}->{$next}) {
         $argv->{table}->{$next} = $list->{$next};
         $argv->{types}->{$next} = $types->{$next};
      } elsif (++$argv->{repeat_cnt} > $argv->{max_reps}) {
         $self->pdu->status_information(
            'A loop was detected with the table on the remote host'
         );
         return;
      }
   }

   # Queue the next request if we are not at the end of the table.
   if (defined $next) {
      $self->_get_table_entries_request_next($argv, $callback, [$next]);
      return;
   }

   # Clear the PDU error on a noSuchName(2) error status.
   if ($self->error_status == 2) {
      $self->pdu->error(undef);
   }

   # Check for an empty or nonexistent table.
   unless ($self->pdu->error && !defined $argv->{table}) {
      $self->pdu->error('The requested table is empty or does not exist');
   }

   # Copy the table to the var_bind_list.
   $self->pdu->var_bind_list($argv->{table}, $argv->{types});

   # Notify the command generator to process the results.
   $self->pdu->process_response_pdu;

   return;
}

### FIXME ###
sub _get_entries_cb {
   my ($self, $argv) = @_;

   # Get the current callback.
   my $callback = $self->pdu->callback;

   # Assign the user callback to the PDU.
   $self->pdu->callback($argv->{callback});

   # Iterate through the response OBJECT IDENTIFIERs.  The response(s)
   # will (should) be grouped in the same order as the columns that
   # were requested.  We use this assumption to map the response(s) to
   # get-next/bulk-requests.  When using get-bulk-requests, "holes" in
   # the table may cause certain columns to run ahead or behind other
   # columns, so we cache all entries and sort it out when processing
   # the row.

   my $list       = $self->var_bind_list;
   my $types      = $self->var_bind_types;
   my @names      = $self->var_bind_names;
   my $max_index  = (defined $argv->{last_index}) ? $argv->{last_index} : '0';
   my $last_entry = TRUE;
   my $cache      = {};

   while (@names) {

      my @row = ();
      my $row_index = undef;

      # Match up the responses to the requested columns.

      for my $col_num (0 .. $#{$argv->{columns}}) {

         my $name = shift @names;

         unless (defined $name) {

            # Due to transport layer limitations, the response could have
            # been truncated, so do not consider this the last entry.

            $self->DEBUG_INFO('column number / oid number mismatch');
            $last_entry = FALSE;
            @row = ();
            last;
         }

         my $column = quotemeta $argv->{columns}->[$col_num];
         my $index;

         if ($name =~ m/$column\.(\d+(:?\.\d+)*)/) {

            # Requested column and response column match up.
            $index = $1;

         } else {

            # The response column does not map to the the request, there
            # could be a "hole" or we are out of entries.

            $last_entry = TRUE;
            next;
         }

         # Validate the index of the response.

         if ((defined $argv->{start_index}) &&
             (oid_lex_cmp($index, $argv->{start_index}) < 0))
         {
            $self->DEBUG_INFO(
               'index [%s] less than start_index [%s]',
               $index, $argv->{start_index}
            );
            if (oid_lex_cmp($index, $max_index) > 0) {
               $max_index = $index;
               $last_entry = FALSE;
               $self->DEBUG_INFO('new max_index [%s]', $max_index);
            }
            next;
         } elsif ((defined $argv->{end_index}) &&
                  (oid_lex_cmp($index, $argv->{end_index}) > 0))
         {
            $self->DEBUG_INFO(
               'last_entry: index [%s] greater than end_index [%s]',
                $index, $argv->{end_index}
            );
            $last_entry = TRUE;
            next;
         }

         # Cache the current column since it falls into the requested range.

         $cache->{$index}->[$col_num] = $name;

         # To handle "holes" in the conceptual row, checks need to be made
         # so that the lowest index for each group of responses is used.

         unless (defined $row_index) {
            $row_index = $index;
         }

         my $index_cmp = oid_lex_cmp($index, $row_index);

         if ($index_cmp == 0) {

            # The index for this response entry matches, so fill in
            # the corresponding row entry.

            $row[$col_num] = $name;

         } elsif ($index_cmp < 0) {

            # The index for this response is less than the current index,
            # so we throw out everything and start over.

            @row = ();
            $row_index = $index;
            $row[$col_num] = $name;

         } else {

            # There must be a "hole" in the row, do nothing here since this
            # entry was cached and will hopefully be taken care of later.

            $self->DEBUG_INFO(
               'index [%s] greater than current row_index [%s]',
               $index, $row_index
            );

         }

      }

      # No row information found, continue.

      unless (@row || !defined $row_index) {
         next;
      }

      # Now store the results for the conceptual row.

      for my $col_num (0 .. $#{$argv->{columns}}) {

         # Check for cached values that may have been lost due to "holes".
         unless (defined $row[$col_num]) {
            if (defined $cache->{$row_index}->[$col_num]) {
               $self->DEBUG_INFO('using cache: %s', $cache->{$row_index}->[$col_num]);
               $row[$col_num] = $cache->{$row_index}->[$col_num];
            } else {
               next;
            }
         }

         # Actually store the results.
         unless (exists $argv->{entries}->{$row[$col_num]}) {
            $last_entry = FALSE;
            $argv->{entries}->{$row[$col_num]} = $list->{$row[$col_num]};
            $argv->{types}->{$row[$col_num]}   = $types->{$row[$col_num]};
         } else {
            $self->DEBUG_INFO('not adding duplicate: %s', $row[$col_num]);
         }

      }

      # Execute the row callback if it is defined.
      $self->_get_entries_exec_row_cb($argv, $row_index, \@row);

      # Store the maximum index found to be used for the next request.
      if (oid_lex_cmp($row_index, $max_index) > 0) {
         $max_index = $row_index;
      }

   }

   # Make sure we are not stuck (looping) on a single index.

   if (defined $argv->{last_index}) {
      if (oid_lex_cmp($max_index, $argv->{last_index}) > 0) {
         $argv->{last_index} = $max_index;
      } elsif ($last_entry == FALSE) {
         $self->DEBUG_INFO(
            'last_entry: max_index [%s] not greater than last_index [%s])',
            $max_index, $argv->{last_index}
         );
         $last_entry = TRUE;
      }
   } else {
      $argv->{last_index} = $max_index;
   }

   # If we have not reached the last requested entry, generate another
   # get-next/bulk-request message.

   if ($last_entry == FALSE) {
      my $vbl = [ map { join q{.}, $_, $max_index } @{$argv->{columns}} ];
      $self->_get_table_entries_request_next($argv, $callback, $vbl);
      return;
   }

   # Clear the PDU error on a noSuchName(2) error status.
   if ($self->error_status == 2) {
      $self->pdu->error(undef);
   }

   # Check for an empty or nonexistent table.
   unless ($self->pdu->error && !defined $argv->{entries}) {
      $self->pdu->error('The requested entries are empty or do not exist');
   }

   # Copy the table to the var_bind_list.
   $self->pdu->var_bind_list($argv->{entries}, $argv->{types});

   # Execute the row callback, if there has been an error.
   if ($self->pdu->error) {
      $self->_get_entries_exec_row_cb($argv, 0, []);
   }

   # Notify the command generator to process the results.
   $self->pdu->process_response_pdu;

   return;
}

### FIXME ###
sub _get_table_entries_request_next {
   my ($self, $argv, $callback, $vbl) = @_;

   # Copy the current PDU for use in error conditions.
   my $pdu = $self->pdu;

   # Create a new PDU.
   unless (defined $self->_create_pdu) {
      $pdu->status_information($self->error);
      return;
   }

   # Override the callback with the saved callback.
   $self->pdu->callback($callback);

   # Use the contextEngineID and contextName from the previous request
   # because the values stored in the object could change.

   if (defined $pdu->context_engine_id) {
      $self->pdu->context_engine_id($pdu->context_engine_id);
   }

   if (defined $pdu->context_name) {
      $self->pdu->context_name($pdu->context_name);
   }

   # Create the appropriate request.

   if ($argv->{use_bulk}) {
      unless (defined $self->pdu->prepare_get_bulk_request(0,
                                                           $argv->{max_reps},
                                                           $vbl))
      {
         $pdu->status_information($self->pdu->error);
         return;
      }
   } else {
      unless (defined $self->pdu->prepare_get_next_request($vbl)) {
         $pdu->status_information($self->pdu->error);
         return;
      }
   }

   # Send the next PDU as a priority
   # (Existing requests get priority over new ones)
   $self->dispatcher->send_pdu_priority($self->pdu);

   return;
}

### FIXME ###
sub _get_entries_exec_row_cb {
   my ($self, $argv, $index, $row) = @_;

   return if !defined $argv->{row_callback};

   my ($cb, @argv) = @{$argv->{row_callback}};

   # Add the "values" found for each column to the front of the
   # callback argument list.

   for (my $col_num = $#{$argv->{columns}}; $col_num >= 0; --$col_num) {
      if (defined $row->[$col_num]) {
         unshift @argv, $argv->{entries}->{$row->[$col_num]};
      } else {
         unshift @argv, undef;
      }
   }

   # Prepend the index for the conceptual row.
   unshift @argv, $index;

   return eval { $cb->(@argv); };
}

sub _error {
   my $self = shift;

   # If the PDU callback is still defined when an error occurs, it
   # needs to be cleared to prevent the closure from holding up the
   # reference count of the object that created the closure.

   $self->pdu->_clear_callback
      if ($self->has_pdu && $self->pdu->has_callback);

   return printf 'debug: [%d] %s(): '.(@_ > 1 ? shift : '%s')."\n", (
      (caller 0)[2],
      (caller 1)[3],
      @_
   );

   unless ($self->has_error) {
      $self->_set_error( @_ > 1 ? sprintf(shift, @_) : $_[0] );
      if ($self->debug && DEBUG_SNMP) {
         printf "error: [%d] %s(): %s\n",
                (caller 0)[2], (caller 1)[3], $self->error;
      }
   }

   return;
}

# [end Net::SNMPu code] -------------------------------------------------------
1;
__END__

# [documentation] ------------------------------------------------------------

=back

=head1 EXAMPLES

=head2 1. Blocking SNMPv1 get-request for sysUpTime

This example gets the sysUpTime from a remote host.

   #! /usr/local/bin/perl

   use strict;
   use warnings;

   use Net::SNMPu;

   my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';

   my ($session, $error) = Net::SNMPu->session(
      -hostname  => shift || 'localhost',
      -community => shift || 'public',
   );

   unless (defined $session) {
      printf "ERROR: %s.\n", $error;
      exit 1;
   }

   my $result = $session->get_request(-varbindlist => [ $OID_sysUpTime ],);

   unless (defined $result) {
      printf "ERROR: %s.\n", $session->error;
      $session->close;
      exit 1;
   }

   printf "The sysUpTime for host '%s' is %s.\n",
          $session->hostname(), $result->{$OID_sysUpTime};

   $session->close;

   exit 0;

=head2 2. Blocking SNMPv3 set-request of sysContact

This example sets the sysContact information on the remote host to
"Help Desk x911".  The named arguments passed to the C<session()> constructor
are for the demonstration of syntax only.  These parameters will need to be
set according to the SNMPv3 parameters of the remote host.  The C<snmpkey>
utility included with the distribution can be used to create the key values.

   #! /usr/local/bin/perl

   use strict;
   use warnings;

   use Net::SNMPu;

   my $OID_sysContact = '1.3.6.1.2.1.1.4.0';

   my ($session, $error) = Net::SNMPu->session(
      -hostname     => 'myv3host.example.com',
      -version      => 'snmpv3',
      -username     => 'myv3Username',
      -authprotocol => 'sha1',
      -authkey      => '0x6695febc9288e36282235fc7151f128497b38f3f',
      -privprotocol => 'des',
      -privkey      => '0x6695febc9288e36282235fc7151f1284',
   );

   unless (defined $session) {
      printf "ERROR: %s.\n", $error;
      exit 1;
   }

   my $result = $session->set_request(
      -varbindlist => [ $OID_sysContact, OCTET_STRING, 'Help Desk x911' ],
   );

   unless (defined $result) {
      printf "ERROR: %s.\n", $session->error;
      $session->close;
      exit 1;
   }

   printf "The sysContact for host '%s' was set to '%s'.\n",
          $session->hostname(), $result->{$OID_sysContact};

   $session->close;

   exit 0;

=head2 3. Non-blocking SNMPv2c get-bulk-request for ifTable

This example gets the contents of the ifTable by sending get-bulk-requests
until the responses are no longer part of the ifTable.  The ifTable can also
be retrieved using the C<get_table()> method.  The ifPhysAddress object in
the table has a syntax of an OCTET STRING.  By default, translation is enabled
and non-printable OCTET STRINGs are translated into a hexadecimal format.
Sometimes the OCTET STRING contains all printable characters and this produces
unexpected output when it is not translated.  The example turns off translation
for OCTET STRINGs and specifically formats the output for the ifPhysAddress
objects.

   #! /usr/local/bin/perl

   use strict;
   use warnings;

   use Net::SNMPu qw(:snmp);

   my $OID_ifTable = '1.3.6.1.2.1.2.2';
   my $OID_ifPhysAddress = '1.3.6.1.2.1.2.2.1.6';

   my ($session, $error) = Net::SNMPu->session(
      -hostname    => shift || 'localhost',
      -community   => shift || 'public',
      -nonblocking => 1,
      -translate   => [-octetstring => 0],
      -version     => 'snmpv2c',
   );

   unless (defined $session) {
      printf "ERROR: %s.\n", $error;
      exit 1;
   }

   my %table; # Hash to store the results

   my $result = $session->get_bulk_request(
      -varbindlist    => [ $OID_ifTable ],
      -callback       => [ \&table_callback, \%table ],
      -maxrepetitions => 10,
   );

   unless (defined $result) {
      printf "ERROR: %s\n", $session->error;
      $session->close;
      exit 1;
   }

   # Now initiate the SNMP message exchange.

   snmp_dispatcher;

   $session->close;

   # Print the results, specifically formatting ifPhysAddress.

   for my $oid (oid_lex_sort(keys %table)) {
      unless (oid_base_match($OID_ifPhysAddress, $oid)) {
         printf "%s = %s\n", $oid, $table{$oid};
      } else {
         printf "%s = %s\n", $oid, unpack 'H*', $table{$oid};
      }
   }

   exit 0;

   sub table_callback
   {
      my ($session, $table) = @_;

      my $list = $session->var_bind_list;

      unless (defined $list) {
         printf "ERROR: %s\n", $session->error;
         return;
      }

      # Loop through each of the OIDs in the response and assign
      # the key/value pairs to the reference that was passed with
      # the callback.  Make sure that we are still in the table
      # before assigning the key/values.

      my @names = $session->var_bind_names;
      my $next  = undef;

      while (@names) {
         $next = shift @names;
         unless (oid_base_match($OID_ifTable, $next)) {
            return; # Table is done.
         }
         $table->{$next} = $list->{$next};
      }

      # Table is not done, send another request, starting at the last
      # OBJECT IDENTIFIER in the response.  No need to include the
      # calback argument, the same callback that was specified for the
      # original request will be used.

      my $result = $session->get_bulk_request(
         -varbindlist    => [ $next ],
         -maxrepetitions => 10,
      );

      unless (defined $result) {
         printf "ERROR: %s.\n", $session->error;
      }

      return;
   }

=head2 4. Non-blocking SNMPv1 get-request and set-request on multiple hosts

This example first polls several hosts for their sysUpTime.  If the poll of
the host is successful, the sysContact and sysLocation information is set on
the host.  The sysContact information is hardcoded to "Help Desk x911" while
the sysLocation information is passed as an argument to the callback.

   #! /usr/local/bin/perl

   use strict;
   use warnings;

   use Net::SNMPu;

   my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';
   my $OID_sysContact = '1.3.6.1.2.1.1.4.0';
   my $OID_sysLocation = '1.3.6.1.2.1.1.6.0';

   # Hash of hosts and location data.

   my %host_data = (
      '10.1.1.2'  => 'Building 1, Second Floor',
      '10.2.1.1'  => 'Building 2, First Floor',
      'localhost' => 'Right here!',
   );

   # Create a session for each host and queue a get-request for sysUpTime.

   for my $host (keys %host_data) {

      my ($session, $error) = Net::SNMPu->session(
         -hostname    => $host,
         -community   => 'private',
         -nonblocking => 1,
      );

      unless (defined $session) {
         printf "ERROR: Failed to create session for host '%s': %s.\n",
                $host, $error;
         next;
      }

      my $result = $session->get_request(
         -varbindlist => [ $OID_sysUpTime ],
         -callback    => [ \&get_callback, $host_data{$host} ],
      );

      unless (defined $result) {
         printf "ERROR: Failed to queue get request for host '%s': %s.\n",
                $session->hostname(), $session->error;
      }

   }

   # Now initiate the SNMP message exchange.

   snmp_dispatcher;

   exit 0;

   sub get_callback
   {
      my ($session, $location) = @_;

      my $result = $session->var_bind_list;

      unless (defined $result) {
         printf "ERROR: Get request failed for host '%s': %s.\n",
                $session->hostname(), $session->error;
         return;
      }

      printf "The sysUpTime for host '%s' is %s.\n",
              $session->hostname(), $result->{$OID_sysUpTime};

      # Now set the sysContact and sysLocation for the host.

      $result = $session->set_request(
         -varbindlist =>
         [
            $OID_sysContact,  OCTET_STRING, 'Help Desk x911',
            $OID_sysLocation, OCTET_STRING, $location,
         ],
         -callback    => \&set_callback,
      );

      unless (defined $result) {
         printf "ERROR: Failed to queue set request for host '%s': %s.\n",
                $session->hostname(), $session->error;
      }

      return;
   }

   sub set_callback
   {
      my ($session) = @_;

      my $result = $session->var_bind_list;

      if (defined $result) {
         printf "The sysContact for host '%s' was set to '%s'.\n",
                $session->hostname(), $result->{$OID_sysContact};
         printf "The sysLocation for host '%s' was set to '%s'.\n",
                $session->hostname(), $result->{$OID_sysLocation};
      } else {
         printf "ERROR: Set request failed for host '%s': %s.\n",
                $session->hostname(), $session->error;
      }

      return;
   }

=head1 REQUIREMENTS

=over

=item *

The non-core modules F<Crypt::DES>, F<Digest::MD5>, and F<Digest::HMAC> are
required to support SNMPv3.

=item *

In order to support the AES Cipher Algorithm as a SNMPv3 privacy protocol, the
non-core module F<Crypt::Rijndael> is needed.

=item *

To use UDP/IPv6 or TCP/IPv6 as a Transport Domain, the non-core module
F<Socket6> is needed.

=back

=head1 DIFFERENCES TO Net::SNMP

Net::SNMPu's interface has some subtle, but important differences to the
original Net::SNMP code.  Most of this was done with the goal of "modernization"
in mind:

=over

=item

All of the classes use L<Moo> for object and method delegation.

=item

Arguments use non-dashed notation as the preferred method.

=item

The C<translate> feature has been removed.  L<Net::SNMP::XS> never supported it,
and I think most people disabled it, anyway.  IMHO, string parsing for things
that aren't strings (like errors) isn't the most ideal way to do things, anyway.

=item

Anything marked as deprecated or "backwards compatible" was removed.

=item

All standalone subs were either removed or put into L<Net::SNMPu::Utils>.

=item

All public constants have been moved to L<Net::SNMPu::Constants>.

=back

=head1 AUTHOR

Brendan Byrd / SineSwiper <BBYRD@CPAN.org>

=head1 ACKNOWLEDGMENTS

David M. Town <dtown@cpan.org> wrote L<Net::SNMP>, which is the ancestor to the
bulk of the code here.  Wes Hardaker wrote the MIB loaders, as well as the
Net-SNMP library.  Marc Lehmann wrote L<Net::SNMP::XS>, which handles the XS
portion of the deeper Transport code.

I put some of my patches in place, cleaned up the code, and merged
them together.

=cut

# ============================================================================
1; # [end Net::SNMPu]
