package Net::SNMPu::Transport::IPv4::UDP;

# ABSTRACT: Object that handles the UDP/IPv4 Transport Domain for the SNMP Engine.

use sanity;
use Net::SNMPu::Transport qw( DOMAIN_UDPIPV4 );
use IO::Socket qw( SOCK_DGRAM );

## Handle importing/exporting of symbols

use parent qw( Net::SNMPu::Transport::IPv4 Net::SNMPu::Transport );

sub import
{
   return Net::SNMPu::Transport->export_to_level(1, @_);
}

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)
use constant {
   MSG_SIZE_DEFAULT_UDP4 => 1472,  # Ethernet(1500) - IPv4(20) - UDP(8)
};

# [public methods] -----------------------------------------------------------

sub new
{
   return shift->SUPER::_new(@_);
}

sub send
{
   my $this = shift;

   $this->_error_clear();

   if (length($_[0]) > $this->{_max_msg_size}) {
      return $this->_error(
         'The message size %d exceeds the maxMsgSize %d',
         length($_[0]), $this->{_max_msg_size}
      );
   }

   my $bytes = $this->{_socket}->send($_[0], 0, $this->{_dest_name});

   return defined($bytes) ? $bytes : $this->_perror('Send failure');
}

sub recv
{
   my $this = shift;

   $this->_error_clear();

   my $name = $this->{_socket}->recv($_[0], $this->_shared_max_size(), 0);

   return defined($name) ? $name : $this->_perror('Receive failure');
}

use constant {
   domain => DOMAIN_UDPIPV4,  # transportDomainUdpIpv4
   type   => 'UDP/IPv4',      # udpIpv4(1)
};

sub agent_addr
{
   my ($this) = @_;

   $this->_error_clear();

   my $name = $this->{_socket}->sockname() || $this->{_sock_name};

   if ($this->{_socket}->connect($this->{_dest_name})) {
      $name = $this->{_socket}->sockname() || $this->{_sock_name};
      if (!$this->{_socket}->connect((pack('x') x length $name))) {
         $this->_perror('Failed to disconnect');
      }
   }

   return $this->_address($name);
}

# [private methods] ----------------------------------------------------------

use constant {
   _protocol_name    => 'udp',
   _protocol_type    => SOCK_DGRAM,
   _msg_size_default => MSG_SIZE_DEFAULT_UDP4,
   _tdomain          => DOMAIN_UDPIPV4,
};

# ============================================================================
1; # [end Net::SNMPu::Transport::IPv4::UDP]

