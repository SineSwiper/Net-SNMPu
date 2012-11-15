package Net::SNMPu::Constants;

# VERSION
# ABSTRACT: Constants used in Net::SNMPu

use constant {
   
   # Debugging
   DEBUG_ALL        => 0xff,  # All
   DEBUG_NONE       => 0x00,  # None
   DEBUG_SNMP       => 0x01,  # Main Net::SNMPu functions
   DEBUG_MESSAGE    => 0x02,  # Message/PDU encoding/decoding
   DEBUG_TRANSPORT  => 0x04,  # Transport Layer
   DEBUG_DISPATCHER => 0x08,  # Dispatcher
   DEBUG_PROCESSING => 0x10,  # Message Processing
   DEBUG_SECURITY   => 0x20,  # Security
   
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

   #TRANSLATE_NONE           => 0x00,  # Bit masks used to determine
   #TRANSLATE_OCTET_STRING   => 0x01,  # if a specific ASN.1 type is
   #TRANSLATE_NULL           => 0x02,  # translated into a "human
   #TRANSLATE_TIMETICKS      => 0x04,  # readable" form.
   #TRANSLATE_OPAQUE         => 0x08,
   #TRANSLATE_NOSUCHOBJECT   => 0x10,
   #TRANSLATE_NOSUCHINSTANCE => 0x20,
   #TRANSLATE_ENDOFMIBVIEW   => 0x40,
   #TRANSLATE_UNSIGNED       => 0x80,
   #TRANSLATE_ALL            => 0xff,

   ## Truth values 

   TRUE                     => 0x01,
   FALSE                    => 0x00,

   # RFC 3417 Transport Mappings for SNMP
   # Presuhn, Case, McCloghrie, Rose, and Waldbusser; December 2002
   DOMAIN_UDP => '1.3.6.1.6.1.1',  # snmpUDPDomain

   # RFC 3419 Textual Conventions for Transport Addresses
   # Consultant, Schoenwaelder, and Braunschweig; December 2002
   DOMAIN_UDPIPV4  => '1.3.6.1.2.1.100.1.1',  # transportDomainUdpIpv4
   DOMAIN_UDPIPV6  => '1.3.6.1.2.1.100.1.2',  # transportDomainUdpIpv6
   DOMAIN_UDPIPV6Z => '1.3.6.1.2.1.100.1.4',  # transportDomainUdpIpv6z
   DOMAIN_TCPIPV4  => '1.3.6.1.2.1.100.1.5',  # transportDomainTcpIpv4
   DOMAIN_TCPIPV6  => '1.3.6.1.2.1.100.1.6',  # transportDomainTcpIpv6
   DOMAIN_TCPIPV6Z => '1.3.6.1.2.1.100.1.8',  # transportDomainTcpIpv6z
   
   ## SNMP well-known ports
   SNMP_PORT            => 161,
   SNMP_TRAP_PORT       => 162,
   
   ## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)
   MSG_SIZE_DEFAULT     =>   484,
   MSG_SIZE_MINIMUM     =>   484,
   MSG_SIZE_MAXIMUM     => 65535,  # 2147483647 is not reasonable
   
   RETRIES_DEFAULT      =>   1,
   RETRIES_MINIMUM      =>   0,
   RETRIES_MAXIMUM      =>  20,
   
   TIMEOUT_DEFAULT      =>   5.0,
   TIMEOUT_MINIMUM      =>   1.0,
   TIMEOUT_MAXIMUM      =>  60.0,
   
   MAX_REQUESTS_DEFAULT =>     3,
   MAX_REQUESTS_MINIMUM =>     0,
   MAX_REQUESTS_MAXIMUM => 65535,
   
};

use parent 'Exporter';

our @EXPORT    = ();
our @EXPORT_OK = ();

our %EXPORT_TAGS = (
   # Main stuff
   debug       => [
      qw( DEBUG_ALL DEBUG_NONE DEBUG_SNMP DEBUG_MESSAGE DEBUG_TRANSPORT
          DEBUG_DISPATCHER DEBUG_PROCESSING DEBUG_SECURITY )
   ],
   generictrap => [
      qw( COLD_START WARM_START LINK_DOWN LINK_UP AUTHENTICATION_FAILURE
          EGP_NEIGHBOR_LOSS ENTERPRISE_SPECIFIC )
   ],
   snmp        => [
      qw( SNMP_VERSION_1 SNMP_VERSION_2C SNMP_VERSION_3 SNMP_PORT 
          SNMP_TRAP_PORT )
   ],
   #translate   => [
   #   qw( TRANSLATE_NONE TRANSLATE_OCTET_STRING TRANSLATE_NULL 
   #       TRANSLATE_TIMETICKS TRANSLATE_OPAQUE TRANSLATE_NOSUCHOBJECT 
   #       TRANSLATE_NOSUCHINSTANCE TRANSLATE_ENDOFMIBVIEW TRANSLATE_UNSIGNED 
   #       TRANSLATE_ALL )
   #],
   bool        => [ qw( TRUE FALSE ) ],

   # Message stuff
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
   types          => [
      qw( INTEGER INTEGER32 OCTET_STRING NULL OBJECT_IDENTIFIER SEQUENCE
          IPADDRESS COUNTER COUNTER32 GAUGE GAUGE32 UNSIGNED32 TIMETICKS
          OPAQUE COUNTER64 NOSUCHOBJECT NOSUCHINSTANCE ENDOFMIBVIEW
          GET_REQUEST GET_NEXT_REQUEST GET_RESPONSE SET_REQUEST TRAP
          GET_BULK_REQUEST INFORM_REQUEST SNMPV2_TRAP REPORT )
   ],
   versions       => [ qw( SNMP_VERSION_1 SNMP_VERSION_2C SNMP_VERSION_3 ) ],

   # Transport stuff
   domains => [
      qw( DOMAIN_UDP DOMAIN_UDPIPV4 DOMAIN_UDPIPV6 DOMAIN_UDPIPV6Z
          DOMAIN_TCPIPV4 DOMAIN_TCPIPV6 DOMAIN_TCPIPV6Z )
   ],
   msgsize => [ qw( MSG_SIZE_DEFAULT MSG_SIZE_MINIMUM MSG_SIZE_MAXIMUM ) ],
   ports   => [ qw( SNMP_PORT SNMP_TRAP_PORT )                           ],
   retries => [ qw( RETRIES_DEFAULT RETRIES_MINIMUM RETRIES_MAXIMUM )    ],
   timeout => [ qw( TIMEOUT_DEFAULT TIMEOUT_MINIMUM TIMEOUT_MAXIMUM )    ],
);

Exporter::export_ok_tags( qw( 
   debug generictrap msgFlags securityLevels securityModels snmp types versions
   domains msgsize ports retries timeout
) );

$EXPORT_TAGS{asn1} = $EXPORT_TAGS{types}; 
$EXPORT_TAGS{ALL}  = [ @EXPORT_OK ];

=head1 DESCRIPTION

The Net::SNMPu::Constants module uses the F<Exporter> module to export useful
constants and subroutines.  These exportable symbols are defined below and
follow the rules and conventions of the L<Exporter> module.

=over

=item Default

Nothing is exported on default.

=item Tags

=over 

=item :asn1 (or :types)

INTEGER, INTEGER32, OCTET_STRING, NULL, OBJECT_IDENTIFIER, SEQUENCE, 
IPADDRESS, COUNTER, COUNTER32, GAUGE, GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, 
COUNTER64, NOSUCHOBJECT, NOSUCHINSTANCE, ENDOFMIBVIEW, GET_REQUEST, 
GET_NEXT_REQUEST, GET_RESPONSE, SET_REQUEST, TRAP, GET_BULK_REQUEST, 
INFORM_REQUEST, SNMPV2_TRAP, REPORT

=item :debug

DEBUG_ALL, DEBUG_NONE, DEBUG_MESSAGE, DEBUG_TRANSPORT, DEBUG_DISPATCHER,
DEBUG_PROCESSING, DEBUG_SECURITY

=item :generictrap

COLD_START, WARM_START, LINK_DOWN, LINK_UP, AUTHENTICATION_FAILURE,
EGP_NEIGHBOR_LOSS, ENTERPRISE_SPECIFIC

=item :snmp

SNMP_VERSION_1, SNMP_VERSION_2C, SNMP_VERSION_3, SNMP_PORT, SNMP_TRAP_PORT

=item :translate

TRANSLATE_NONE, TRANSLATE_OCTET_STRING, TRANSLATE_NULL, TRANSLATE_TIMETICKS,
TRANSLATE_OPAQUE, TRANSLATE_NOSUCHOBJECT, TRANSLATE_NOSUCHINSTANCE, 
TRANSLATE_ENDOFMIBVIEW, TRANSLATE_UNSIGNED, TRANSLATE_ALL

=item :ALL

All of the above exportable items.

=back
