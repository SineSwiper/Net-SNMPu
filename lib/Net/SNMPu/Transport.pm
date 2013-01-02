package Net::SNMPu::Transport;

# ABSTRACT: Base object for the Net::SNMPu Transport Domain objects.

use sanity;
use Moo;
use MooX::Types::MooseLike::Base qw(InstanceOf ScalarRef ArrayRef Str Int);

use Net::SNMPu::Constants qw(DEBUG_TRANSPORT SEQUENCE :domains :msgsize :maxreq :ports :retries :timeout :bool);

use IO::Socket::IP;
use List::AllUtils 'max';

### FIXME ###
use constant {
   ## Shared socket array indexes
   _SHARED_SOCKET  => 0,   # Shared Socket object
   _SHARED_REFC    => 1,   # Reference count
   _SHARED_MAXSIZE => 2,   # Shared maxMsgSize
};

### FIXME ###
## Package variables
our $SOCKETS = {};                  # List of shared sockets

around BUILDARGS => sub {
   my ($orig, $self) = (shift, shift);
   my $hash = $self->_argument_munge(@_);

   return $orig->($self, $hash)
      if ($hash->{_socket} && $hash->{_dest});

   my $newhash = {
      dest_hostname => 'localhost',
      dest_port     => 'snmp(161)',  # embedded ports in hostnames will override this
   };

   # Just get the arguments, and let IO::Socket::IP handle validation.
   state $trans_argv = {qw{
      hostname                 dest_hostname
      (?:de?st|peer)?addr      dest_hostname
      (?:de?st|peer)?port      dest_port
      (?:src|sock|local)addr   sock_hostname
      (?:src|sock|local)port   sock_port
      max_?requests?           max_requests
      max_?msg_?size|mtu       max_msg_size

      retries  retries
      timeout  timeout
      domain   domain
      listen   listen

      session  session
   }};

   foreach my $key (keys %$hash) {
      foreach my $re (keys %$trans_argv) {
         if ($key =~ /^$re$/i) {
            $newhash->{ $trans_argv->{$re} } = delete $hash->{$key};
            last;
         }
      }
      if ($hash->{$key}) {  # should have been deleted by now...
         $hash->{session}->_error('The argument "%s" is unknown', $key);
         return;
      }
   }
   my $session = $newhash->{session};

   # Translate/split domain
   state $domains = {
      'udp/?(?:ip)?v?4?'        => DOMAIN_UDPIPV4,
      quotemeta DOMAIN_UDP      => DOMAIN_UDPIPV4,
      quotemeta DOMAIN_UDPIPV4  => DOMAIN_UDPIPV4,

      'udp/?(?:ip)?v?6'         => DOMAIN_UDPIPV6,
      quotemeta DOMAIN_UDPIPV6  => DOMAIN_UDPIPV6,
      quotemeta DOMAIN_UDPIPV6Z => DOMAIN_UDPIPV6,

      'tcp/?(?:ip)?v?4?'        => DOMAIN_TCPIPV4,
      quotemeta DOMAIN_TCPIPV4  => DOMAIN_TCPIPV4,

      'tcp/?(?:ip)?v?6'         => DOMAIN_TCPIPV6,
      quotemeta DOMAIN_TCPIPV6  => DOMAIN_TCPIPV6,
      quotemeta DOMAIN_TCPIPV6Z => DOMAIN_TCPIPV6,
   };

   foreach my $re (keys %$domains) {
      if ($newhash->{domain} =~ /^$re$/i) {
         $newhash->{domain} = $domains->{$re};
         last;
      }
   }
   $newhash->{domain} //= DOMAIN_UDPIPV4;

   my ($proto, $domain, $size);
   for ($newhash->{domain}) {
      when (DOMAIN_UDPIPV4) { ($proto, $domain, $size) = ('udp', PF_INET , 1472); }  # Ethernet(1500) - IPv4(20) - UDP(8)
      when (DOMAIN_UDPIPV6) { ($proto, $domain, $size) = ('udp', PF_INET6, 1452); }  # Ethernet(1500) - IPv6(40) - UDP(8)
      when (DOMAIN_TCPIPV4) { ($proto, $domain, $size) = ('tcp', PF_INET , 1460); }  # Ethernet(1500) - IPv4(20) - TCP(20)
      when (DOMAIN_TCPIPV6) { ($proto, $domain, $size) = ('tcp', PF_INET6, 1440); }  # Ethernet(1500) - IPv6(40) - TCP(20)
      default {
         $session->_error('The domain value "%s" is invalid', $newhash->{domain});
         return;
      }
   }

   $newhash->{max_msg_size} ||= $size;  # RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)

   # Translate the IO::Socket::IP arguments
   state $trans2isi = {qw{
      dest_hostname   PeerAddr
      dest_port       PeerPort
      sock_hostname   LocalAddr
      sock_port       LocalPort
      listen          Listen
   }};

   my $sock_args = {};
   foreach my $key (keys %$trans2isi) {
      $sock_args->{ $trans2isi->{$key} } = delete $newhash->{$key}
         if ($newhash->{$key});
   }

   # Put back the *_hostnames
   $newhash->{sock_hostname} = $sock_args->{LocalAddr};
   $newhash->{dest_hostname} = $sock_args->{PeerAddr};

   $sock_args->{Proto}    = $proto;
   $sock_args->{Domain}   = $domain;
   $sock_args->{Type}     = $proto eq 'tcp' ? SOCK_STREAM : SOCK_DGRAM;
   $sock_args->{Blocking} = FALSE;

   # Build dest_args and remove destination if UDP
   my $dest_args = { %$sock_args };
   if ($proto eq 'udp') {
      delete $sock_args->{PeerAddr};
      delete $sock_args->{PeerPort};
   }

   # Build the "info" socket first
   unless ( $newhash->{_dest} = IO::Socket::IP->new(%$dest_args) ) {
      $session->_error('Cannot create dest socket: %s', $!);
      return;
   }

   # For all connection-oriented transports and for each unique source
   # address for connectionless transports, create a new socket.
   my ($sock_name, $dest_name) = ($newhash->{_dest}->sockname, $newhash->{_dest}->peername);

   if ($proto eq 'tcp' || !exists $SOCKETS->{$sock_name}) {
      # Create the real socket
      unless ( $newhash->{_socket} = IO::Socket::IP->new(%$sock_args) ) {
         $session->_error('Cannot create new socket: %s', $!);
         return;
      }
      my $socket = $newhash->{_socket};
      $self->DEBUG_INFO('opened %s/%s socket [%d]', $proto, $domain, $socket->fileno);

      # Bind the socket.
      if (!defined $socket->bind($sock_name)) {
         $session->_error('Failed to bind %s/%s socket: %s', $proto, $domain, $!);
         return;
      }

      # For connection-oriented transports, we either listen or connect.
      if ($proto eq 'tcp') {
         if ($sock_args->{Listen}) {
            if (!defined $socket->listen($sock_name)) {
               $session->_error('Failed to listen on %s/%s socket: %s', $proto, $domain, $!);
               return;
            }
         }
         else {
            if (!defined $socket->connect($dest_name)) {
               $session->_error("Failed to connect to remote host '%s': %s", $newhash->{dest_hostname}, $!);
               return;
            }
         }
      }

      ### TODO: This needs to be changed to something a bit more thread safe... ###

      # Add the socket to the global socket list with a reference
      # count to track when to close the socket and the maxMsgSize
      # associated with this new object for connectionless transports.

      if ($proto eq 'udp') {
         $newhash->{_sock_param} = $SOCKETS->{$sock_name} = [
            $newhash->{socket},        # Shared Socket object
            1,                         # Reference count
            $newhash->{max_msg_size},  # Shared maximum message size
         ];
      }
      else {
         # Reassembly buffer required for TCP
         $newhash->{_reasm_object} = Net::SNMPu::Message->new;
      }
   }
   else {
      # Bump up the reference count.
      $SOCKETS->{$sock_name}->[_SHARED_REFC]++;

      # Assign the socket to the object.
      my $socket = $newhash->{_socket}     = $SOCKETS->{$sock_name}->[_SHARED_SOCKET];
      my $sparam = $newhash->{_sock_param} = $SOCKETS->{$sock_name};

      # Adjust the shared maxMsgSize if necessary.
      $sparam->[_SHARED_MAXSIZE] = $newhash->{max_msg_size} = max($sparam->[_SHARED_MAXSIZE], $newhash->{max_msg_size});

      $self->DEBUG_INFO('reused %s/%s socket [%d]', $proto, $domain, $socket->fileno);
   }

   $orig->($self, $newhash);
};

# [attributes] ------------------------------------------------------------------

has max_msg_size => (
   is      => 'rw',
   isa     => sub { __validate_posnum('maxMsgSize', $_[0], MSG_SIZE_MINIMUM, MSG_SIZE_MAXIMUM); },
   trigger => sub {
      my ($self, $val, $oldval) = @_;
      if ($self->_has_sock_param) {
         return $self->_sock_param->[_SHARED_MAXSIZE] = max($self->_sock_param->[_SHARED_MAXSIZE], $val);
      }
      return $val;
   },
);

has max_requests => (
   is      => 'rw',
   isa     => sub { __validate_posnum('max requests', $_[0], MAX_REQUESTS_MINIMUM, MAX_REQUESTS_MAXIMUM); },
   lazy    => 1,
   default => sub { MAX_REQUESTS_DEFAULT },
);

has retries => (
   is      => 'rw',
   isa     => sub { __validate_posnum('retries', $_[0], RETRIES_MINIMUM, RETRIES_MAXIMUM); },
   lazy    => 1,
   default => sub { RETRIES_DEFAULT },
);

has timeout => (
   is      => 'rw',
   isa     => sub { __validate_posnum('timeout', $_[0], TIMEOUT_MINIMUM, TIMEOUT_MAXIMUM); },
   lazy    => 1,
   default => sub { TIMEOUT_DEFAULT },
);

sub __validate_posnum {
   my ($type, $num, $min, $max) = @_;
   die sprintf(
      'The %s value "%s" is expected in positive numeric format',
      $type, $num
   ) unless ($type eq 'timeout' ? $num =~ /^\d+(?:\.\d+)?$/ : $num =~ /^\d+$/);

   die sprintf(
      'The %s value "%s" is out of range (%d..%d)',
      $type, $num, $min, $max
   ) if ($num < $min || $num > $max);

   return TRUE;
}

has session => (
   is        => 'ro',
   isa       => InstanceOf['Net::SNMPu'],
   predicate => 1,
   handles   => [qw(
      debug
      error
      _error
      _clear_error
      _argument_munge
   )],
);

sub DEBUG_INFO {
   return if ($_[0]->debug && DEBUG_TRANSPORT);  # first for hot-ness
   shift;  # $self; not needed here

   return printf 'debug: [%d] %s(): '.(@_ > 1 ? shift : '%s')."\n", (
      (caller 0)[2],
      (caller 1)[3],
      @_
   );
}

# Online, in-use socket
has socket => (
   is        => 'ro',
   isa       => InstanceOf['IO::Socket::IP'],
   predicate => 1,
   init_arg  => '_socket',
   handles   => {qw{
      fileno      fileno
      connected   connected

      sockhost    sock_address
      sockport    sock_port
      sockaddr    sock_addr
      sockdomain  sock_domain
      sockname    sock_name
      sockscope   sock_scope_id
      sockflow    sock_flowinfo

      peerhost    peer_address
      peerport    peer_port
      peeraddr    peer_addr
      peerdomain  peer_domain
      peername    peer_name
      peerscope   peer_scope_id
      peerflow    peer_flowinfo
   }},
);

has _sock_param => (
   is        => 'ro',
   isa       => ArrayRef,
   predicate => 'connectionless',
);

# Socket object only for the purposes of storing destination information
has dest => (
   is        => 'ro',
   isa       => InstanceOf['IO::Socket::IP'],
   predicate => 1,
   init_arg  => '_dest',
   handles   => {qw{
      peerhost    dest_address
      peerport    dest_port
      peeraddr    dest_addr
      peerdomain  dest_domain
      peername    dest_name
      peerscope   dest_scope_id
      peerflow    dest_flowinfo
   }},
);

has sock_hostname => (
   is        => 'ro',
   isa       => Str,
   predicate => 1,
);
has dest_hostname => (
   is        => 'ro',
   isa       => Str,
   predicate => 1,
);

has _reasm_object => (
   is        => 'ro',
   isa       => InstanceOf['Net::SNMPu::Message'],
   predicate => 1,
);
has _reasm_buffer => (
   is        => 'rw',
   isa       => ScalarRef[Str],
   predicate => 1,
   clearer   => 1,
);
has _reasm_length => (
   is        => 'rw',
   isa       => Int,
   clearer   => 1,
);

### FIXME: Replace occurrences with sock_address ###
#sub agent_addr { return shift->sock_address; }

# [public methods] -----------------------------------------------------------

sub accept {
   my $self = shift;
   $self->_clear_error;

   my $socket = $self->socket->accept || return $self->_error('Failed to accept the connection');

   $self->DEBUG_INFO('accepted %s/%s socket [%d]', $socket->protocol, $socket->sockdomain, $socket->fileno);

   # Create a new object by copying the current object.
   return $self->new(
      _socket       => $socket,
      _dest         => $socket,
      _reasm_object => Net::SNMPu::Message->new,
      _sock_param   => $self->_sock_param,
      session       => $self->session,
      sock_hostname => $self->sock_hostname,
      dest_hostname => $socket->sockhost,

      max_msg_size  => $self->max_msg_size,
      max_requests  => $self->max_requests,
      retries       => $self->retries,
      timeout       => $self->timeout,
   );
}

sub send {
   my $self = shift;
   $self->_clear_error;

   if (length($_[0]) > $self->max_msg_size) {
      return $self->_error(
         'The message size %d exceeds the maxMsgSize %d',
         length($_[0]), $self->max_msg_size
      );
   }

   unless ($self->connectionless || $self->connected) {
      return $self->_error(
         "Not connected to the remote host '%s'", $self->dest_hostname
      );
   }

   return $self->socket->send(
      $_[0], 0,
      $self->connectionless ? $self->dest_name : ()
   ) // $self->_error('Send failure: %s', $!);
}

sub recv {
   my $self = shift;
   $self->_clear_error;

   # Short and simple UDP version
   if ($self->connectionless) {
      return $self->socket->recv(
         $_[0], $self->max_msg_size, 0
      ) // $self->_error('Receive failure: %s', $!);
   }

   unless ($self->connected) {
      $self->_reasm_reset;
      return $self->_error(
         "Not connected to the remote host '%s'", $self->dest_hostname
      );
   }

   # RCF 3430 Section 2.1 - "It is possible that the underlying TCP
   # implementation delivers byte sequences that do not align with
   # SNMP message boundaries.  A receiving SNMP engine MUST therefore
   # use the length field in the BER-encoded SNMP message to separate
   # multiple requests sent over a single TCP connection (framing).
   # An SNMP engine which looses framing (for example due to ASN.1
   # parse errors) SHOULD close the TCP connection."

   # If the reassembly buffer is empty then there is no partial message
   # waiting for completion.  We must then process the message length
   # to properly determine how much data to receive.

   unless ($self->_has_reasm_buffer) {
      return $self->_error('The reassembly object is not defined')
         unless $self->_has_reasm_object;
      my $reasm = $self->_reasm_object;

      # Read enough data to parse the ASN.1 type and length.
      my $buffer = '';
      my $name = $self->socket->recv($buffer, 6, 0);

      unless (defined $name && not $!) {
         $self->_reasm_reset;
         return $self->_error('Receive failure: %s', $!);
      }
      elsif (!length $buffer) {
         $self->_reasm_reset;
         return $self->_error("The connection was closed by the remote host '%s'", $self->dest_hostname);
      }

      $reasm->append($buffer);

      my $len = $reasm->process(SEQUENCE) || 0;
      if (!$len || $len > MSG_SIZE_MAXIMUM) {
         $self->_reasm_reset;
         return $self->_error("Message framing was lost with the remote host '%s'", $self->dest_hostname);
      }

      # Add in the bytes parsed to define the expected message length.
      $len += $reasm->index;

      # Store attributes
      $self->_reasm_buffer(\$buffer);
      $self->_reasm_length($len);
   }

   # Setup a temporary buffer for the message and set the length
   # based upon the contents of the reassembly buffer.

   my $rbuffer = $self->_reasm_buffer;
   my $buf     = '';
   my $buf_len = length $$rbuffer;

   # Read the rest of the message.
   my $name = $self->socket->recv($buf, ($self->_reasm_length - $buf_len), 0);

   unless (defined $name && not $!) {
      $self->_reasm_reset;
      return $self->_error('Receive failure: %s', $!);
   }
   elsif (!length $buf) {
      $self->_reasm_reset;
      return $self->_error("The connection was closed by the remote host '%s'", $self->dest_hostname);
   }

   # Now see if we have the complete message.  If it is not complete,
   # success is returned with an empty buffer.  The application must
   # continue to call recv() until the message is reassembled.

   $buf_len += length $buf;
   $$rbuffer .= $buf;

   if ($buf_len < $self->_reasm_length) {
      $self->DEBUG_INFO(
         'message is incomplete (expect %u bytes, have %u bytes)',
         $self->_reasm_length, $buf_len
      );
      $_[0] = '';
      return $name || $self->connected;
   }

   # Validate the maxMsgSize.
   if ($buf_len > $self->max_msg_size) {
      $self->_reasm_reset;
      return $self->_error(
         'Incoming message size %d exceeded the maxMsgSize %d',
         $buf_len, $self->max_msg_size
      );
   }

   # The message is complete, copy the buffer to the caller.
   $_[0] = $$rbuffer;

   # Clear the reassembly buffer and length.
   $self->_reasm_reset;

   return $name || $self->connected;
}

sub DEMOLISH {
   my ($self) = @_;

   # Connection-oriented transports do not share sockets.
   return if !$self->connectionless;

   # If the shared socket structure exists, decrement the reference count
   # and clear the shared socket structure if it is no longer being used.

   my $sock_name = $self->sock_name;
   if (defined($sock_name) && exists $SOCKETS->{$sock_name}) {
      if (--$SOCKETS->{$sock_name}->[_SHARED_REFC] < 1) {
         delete $SOCKETS->{$sock_name};
      }
   }

   return;
}

# [private methods] ----------------------------------------------------------

sub _reasm_reset {
   my $self = shift;

   if ($self->_has_reasm_object) {
      $self->_reasm_object->_clear_error;
      $self->_reasm_object->clear;
   }
   $self->_clear_reasm_buffer;
   $self->_clear_reasm_length;
}

# ============================================================================
1; # [end Net::SNMPu::Transport]
