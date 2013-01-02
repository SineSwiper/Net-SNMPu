use Convert::ASN1 ':io';
use Data::Dump;

my $asn = Convert::ASN1->new(
   decode => {
      null => undef,
   }
);
$asn->prepare(<<ASN) or die "prepare: ", $asn->error;
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

#dd $asn;

my $msg_obj = $asn->find('SNMPv123Message');
my $msg = $msg_obj->encode({
   snmpv12 => {
      version => 1,
      community => 'cblemx',
      data => {
         'get-request' => {
            'request-id'   => int(rand(55555)),
            'error-status' => 0,
            'error-index'  => 0,
            'variable-bindings' => [
               { name => '.1.3.6.1.2.1.1.1.0', unSpecified => 0 }
            ],
         }
      }
   }
}) or die "encode: ", $msg_obj->error;

dd $msg;
dd $msg_obj->decode($msg);

use IO::Socket::IP;
use IO::Select;

my $sock = IO::Socket::IP->new(
   LocalPort => 0,
   PeerHost  => "74.128.1.1",
   PeerPort  => "161",
   Proto     => "udp",
   Type      => SOCK_DGRAM,
) or die "Cannot construct socket - $@";

$sock->send($msg) or die "send: ", $!;

my $buffer;
print "SELECTING...\n";
my $select = IO::Select->new($sock) or die "IO::Select $!";
$select->can_read(10);
print "FOUND!\n";

my $ip = $sock->recv($buffer, 1500, 0) or die "recv: ", $!;

dd $buffer;
dd $msg_obj->decode($buffer);
