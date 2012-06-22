package Net::SNMPu::Transport::IPv6::UDP;

# ABSTRACT: Object that handles the UDP/IPv6 Transport Domain for the SNMP Engine.

use sanity;
use Net::SNMPu::Transport::IPv4::UDP qw( DOMAIN_UDPIPV6 DOMAIN_UDPIPV6Z );

## Handle importing/exporting of symbols
use parent qw( Net::SNMPu::Transport::IPv6 Net::SNMPu::Transport::IPv4::UDP );

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)
use constant {
   MSG_SIZE_DEFAULT_UDP6 => 1452  # Ethernet(1500) - IPv6(40) - UDP(8)
};

# [public methods] -----------------------------------------------------------

use constant {
   domain => DOMAIN_UDPIPV6,  # transportDomainUdpIpv6
   type   => 'UDP/IPv6',      # udpIpv6(2)
};

# [private methods] ----------------------------------------------------------

use constant {
   _msg_size_default => MSG_SIZE_DEFAULT_UDP6,
};

sub _tdomain {
   return $_[0]->_scope_id($_[1]) ? DOMAIN_UDPIPV6Z : DOMAIN_UDPIPV6;
}

# ============================================================================
1; # [end Net::SNMPu::Transport::IPv6::UDP]
