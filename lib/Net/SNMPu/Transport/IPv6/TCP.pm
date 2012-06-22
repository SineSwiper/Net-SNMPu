package Net::SNMPu::Transport::IPv6::TCP;

# ABSTRACT: Object that handles the TCP/IPv6 Transport Domain for the SNMP Engine.

use sanity;
use Net::SNMPu::Transport::IPv4::TCP qw( DOMAIN_TCPIPV6 DOMAIN_TCPIPV6Z );

## Handle importing/exporting of symbols
use parent qw( Net::SNMPu::Transport::IPv6 Net::SNMPu::Transport::IPv4::TCP );

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)
use constant {
   MSG_SIZE_DEFAULT_TCP6 => 1440  # Ethernet(1500) - IPv6(40) - TCP(20)
};

# [public methods] -----------------------------------------------------------

use constant {
   domain => DOMAIN_TCPIPV6,  # transportDomainTcpIpv6
   type   => 'TCP/IPv6',      # tcpIpv6(6)
};

# [private methods] ----------------------------------------------------------

use constant {
   _msg_size_default => MSG_SIZE_DEFAULT_TCP6,
};

sub _tdomain {
   return $_[0]->_scope_id($_[1]) ? DOMAIN_TCPIPV6Z : DOMAIN_TCPIPV6;
}

# ============================================================================
1; # [end Net::SNMPu::Transport::IPv6::TCP]

