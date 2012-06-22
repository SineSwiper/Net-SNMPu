package Net::SNMPu::Security::USM;

# ABSTRACT: Object that implements the SNMPv3 User-based Security Model.

use sanity;
use Class::Load;

use Crypt::DES();
use Digest::MD5();
use Digest::SHA();
use Digest::HMAC();

## Handle importing/exporting of symbols

use Net::SNMPu::Security qw( :ALL );
use Net::SNMPu::Message qw(
   :msgFlags asn1_itoa OCTET_STRING SEQUENCE INTEGER SNMP_VERSION_3 TRUE FALSE
);

use parent 'Net::SNMPu::Security';

our @EXPORT_OK;
our %EXPORT_TAGS = (
   authprotos => [
      qw( AUTH_PROTOCOL_NONE AUTH_PROTOCOL_HMACMD5 AUTH_PROTOCOL_HMACSHA )
   ],
   levels     => [
      qw( SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV
          SECURITY_LEVEL_AUTHPRIV )
   ],
   models     => [
      qw( SECURITY_MODEL_ANY SECURITY_MODEL_SNMPV1 SECURITY_MODEL_SNMPV2C
          SECURITY_MODEL_USM )
   ],
   privprotos => [
      qw( PRIV_PROTOCOL_NONE PRIV_PROTOCOL_DES PRIV_PROTOCOL_AESCFB128
          PRIV_PROTOCOL_DRAFT_3DESEDE PRIV_PROTOCOL_DRAFT_AESCFB128
          PRIV_PROTOCOL_DRAFT_AESCFB192 PRIV_PROTOCOL_DRAFT_AESCFB256 )
   ],
);

Exporter::export_ok_tags( qw( authprotos levels models privprotos ) );

$EXPORT_TAGS{ALL} = [ @EXPORT_OK ];
   
use constant {
   ## RCC 3414 - Authentication protocols
   AUTH_PROTOCOL_NONE    => '1.3.6.1.6.3.10.1.1.1',  # usmNoAuthProtocol
   AUTH_PROTOCOL_HMACMD5 => '1.3.6.1.6.3.10.1.1.2',  # usmHMACMD5AuthProtocol
   AUTH_PROTOCOL_HMACSHA => '1.3.6.1.6.3.10.1.1.3',  # usmHMACSHAAuthProtocol

   ## RFC 3414 - Privacy protocols
   PRIV_PROTOCOL_NONE    => '1.3.6.1.6.3.10.1.2.1',  # usmNoPrivProtocol
   PRIV_PROTOCOL_DES     => '1.3.6.1.6.3.10.1.2.2',  # usmDESPrivProtocol

   ## RFC 3826 - The AES Cipher Algorithm in the SNMP USM 

   # usmAesCfb128Protocol
   PRIV_PROTOCOL_AESCFB128        =>  '1.3.6.1.6.3.10.1.2.4',

   # The privacy protocols below have been implemented using the draft 
   # specifications intended to extend the User-based Security Model 
   # defined in RFC 3414.  Since the object definitions have not been 
   # standardized, they have been based on the Extended Security Options 
   # Consortium MIB found at http://www.snmp.com/eso/esoConsortiumMIB.txt.

   # Extension to Support Triple-DES EDE <draft-reeder-snmpv3-usm-3desede-00.txt> 
   # Reeder and Gudmunsson; October 1999, expired April 2000 

   # usm3DESPrivProtocol 
   PRIV_PROTOCOL_DRAFT_3DESEDE    => '1.3.6.1.4.1.14832.1.1',

   # AES Cipher Algorithm in the USM <draft-blumenthal-aes-usm-04.txt>
   # Blumenthal, Maino, and McCloghrie; October 2002, expired April 2003 

   # usmAESCfb128PrivProtocol 
   PRIV_PROTOCOL_DRAFT_AESCFB128  => '1.3.6.1.4.1.14832.1.2',

   # usmAESCfb192PrivProtocol 
   PRIV_PROTOCOL_DRAFT_AESCFB192  => '1.3.6.1.4.1.14832.1.3',

   # usmAESCfb256PrivProtocol
   PRIV_PROTOCOL_DRAFT_AESCFB256  => '1.3.6.1.4.1.14832.1.4',
   
   # Array indexs for $_PROTOCOL_DATA
   _SUB_SUFFIX => 0,
   _KEY_LENGTH => 1,
   _KEY_NAME   => 2,
};

## Private "constant" for AUTH/PRIV_PROTOCOLs
my $_PROTOCOL_DATA = {
   # [sub suffix, key length, key name]  # key length section
   PRIV_PROTOCOL_DES()             => ['des',       16, 'CBC-DES'        ],  # RFC 3414 Section 8.2.1
   PRIV_PROTOCOL_DRAFT_3DESEDE()   => ['3desede',   32, 'CBC-3DES-EDE'   ],  # Draft 3DES for USM Section 5.2.1
   PRIV_PROTOCOL_AESCFB128()       => ['aescfbxxx', 16, 'CFB128-AES-128' ],  # AES in the USM Section 3.2.1
   PRIV_PROTOCOL_DRAFT_AESCFB192() => ['aescfbxxx', 24, 'CFB128-AES-192' ],  # Draft AES in the USM Section 3.2.1
   PRIV_PROTOCOL_DRAFT_AESCFB256() => ['aescfbxxx', 32, 'CFB128-AES-256' ],  # Draft AES in the USM Section 3.2.1

   AUTH_PROTOCOL_HMACMD5()         => [ '',         16, 'HMAC-MD5'  ],
   AUTH_PROTOCOL_HMACSHA()         => [ '',         20, 'HMAC-SHA1' ],
};

## Package variables

our $ENGINE_ID;  # Our authoritative snmpEngineID
# [public methods] -----------------------------------------------------------

sub new {
   my ($class, %argv) = @_;

   # Create a new data structure for the object
   my $this = bless {
      '_error'              => undef,                 # Error message
      '_version'            => SNMP_VERSION_3,        # version 
      '_authoritative'      => FALSE,                 # Authoritative flag
      '_discovered'         => FALSE,                 # Engine discovery flag
      '_synchronized'       => FALSE,                 # Synchronization flag
      '_engine_id'          => q{},                   # snmpEngineID
      '_engine_boots'       => 0,                     # snmpEngineBoots
      '_engine_time'        => 0,                     # snmpEngineTime
      '_latest_engine_time' => 0,                     # latestReceivedEngineTime
      '_time_epoc'          => time(),                # snmpEngineBoots epoc
      '_user_name'          => q{},                   # securityName 
      '_auth_data'          => undef,                 # Authentication data
      '_auth_key'           => undef,                 # authKey 
      '_auth_password'      => undef,                 # Authentication password 
      '_auth_protocol'      => AUTH_PROTOCOL_HMACMD5, # authProtocol
      '_priv_data'          => undef,                 # Privacy data
      '_priv_key'           => undef,                 # privKey 
      '_priv_password'      => undef,                 # Privacy password
      '_priv_protocol'      => PRIV_PROTOCOL_DES,     # privProtocol
      '_security_level'     => SECURITY_LEVEL_NOAUTHNOPRIV
   }, $class;

   # We first need to find out if we are an authoritative SNMP
   # engine and set the authProtocol and privProtocol if they 
   # have been provided.

   foreach (keys %argv) {

      if (/^-?authoritative$/i) {
         $this->{_authoritative} = (delete $argv{$_}) ? TRUE : FALSE;
      } elsif (/^-?authprotocol$/i) {
         $this->_auth_protocol(delete $argv{$_});
      } elsif (/^-?privprotocol$/i) {
         $this->_priv_protocol(delete $argv{$_});
      }

      if (defined $this->{_error}) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }
   }

   # Now validate the rest of the passed arguments

   for (keys %argv) {

      if (/^-?version$/i) {
         $this->_version($argv{$_});
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif ((/^-?engineid$/i) && ($this->{_authoritative})) {
         $this->_engine_id($argv{$_});
      } elsif (/^-?username$/i) {
         $this->_user_name($argv{$_});
      } elsif (/^-?authkey$/i) {
         $this->_auth_key($argv{$_});
      } elsif (/^-?authpassword$/i) {
         $this->_auth_password($argv{$_});
      } elsif (/^-?privkey$/i) {
         $this->_priv_key($argv{$_});
      } elsif (/^-?privpassword$/i) {
         $this->_priv_password($argv{$_});
      } else {
         $this->_error('The argument "%s" is unknown', $_);
      }

      if (defined $this->{_error}) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }

   }

   # Generate a snmpEngineID and populate the object accordingly
   # if we are an authoritative snmpEngine.

   if ($this->{_authoritative}) {
      $this->_snmp_engine_init();
   }

   # Define the securityParameters
   if (!defined $this->_security_params()) {
      return wantarray ? (undef, $this->{_error}) : undef;
   }

   # Return the object and an empty error message (in list context)
   return wantarray ? ($this, q{}) : $this;
}

sub generate_request_msg {
   my ($this, $pdu, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear();

   if (@_ < 3) {
      return $this->_error('The required PDU and/or Message object is missing');
   }

   # Validate the SNMP version of the PDU
   if ($pdu->version() != $this->{_version}) {
      return $this->_error(
         'The SNMP version %d was expected, but %d was found',
         $this->{_version}, $pdu->version()
      );
   }

   # Validate the securityLevel of the PDU
   if ($pdu->security_level() > $this->{_security_level}) {
      return $this->_error(
         'The PDU securityLevel %d is greater than the configured value %d',
         $pdu->security_level(), $this->{_security_level}
      );
   }

   # Validate PDU type with snmpEngine type
   if ($pdu->expect_response()) {
      if ($this->{_authoritative}) {
         return $this->_error(
            'Must be a non-authoritative SNMP engine to generate a %s',
            asn1_itoa($pdu->pdu_type())
         );
      }
   } else {
      if (!$this->{_authoritative}) {
         return $this->_error(
            'Must be an authoritative SNMP engine to generate a %s',
            asn1_itoa($pdu->pdu_type())
         );
      }
   }

   # Extract the msgGlobalData out of the message
   my $msg_global_data = $msg->clear();

   # AES in the USM Section 3.1.2.1 - "The 128-bit IV is obtained as
   # the concatenation of the... ...snmpEngineBoots, ...snmpEngineTime,
   # and a local 64-bit integer.  We store the current snmpEngineBoots
   # and snmpEngineTime before encrypting the PDU so that the computed
   # IV matches the transmitted msgAuthoritativeEngineBoots and
   # msgAuthoritativeEngineTime.

   my $msg_engine_time  = $this->_engine_time();
   my $msg_engine_boots = $this->_engine_boots();

   # Copy the PDU into a "plain text" buffer
   my $pdu_buffer  = $pdu->copy();
   my $priv_params = q{};

   # encryptedPDU::=OCTET STRING
   if ($pdu->security_level() > SECURITY_LEVEL_AUTHNOPRIV) {
      if (!defined $this->_encrypt_data($msg, $priv_params, $pdu_buffer)) {
         return $this->_error();
      }
   }

   # msgPrivacyParameters::=OCTET STRING
   if (!defined $msg->prepare(OCTET_STRING, $priv_params)) {
      return $this->_error($msg->error());
   }

   # msgAuthenticationParameters::=OCTET STRING

   my $auth_params = q{};
   my $auth_location = 0;

   if ($pdu->security_level() > SECURITY_LEVEL_NOAUTHNOPRIV) {

      # Save the location to fill in msgAuthenticationParameters later
      $auth_location = $msg->length() + 12 + length $pdu_buffer;

      # Set the msgAuthenticationParameters to all zeros
      $auth_params = pack 'x12';
   }

   if (!defined $msg->prepare(OCTET_STRING, $auth_params)) {
      return $this->_error($msg->error());
   }

   # msgUserName::=OCTET STRING 
   if (!defined $msg->prepare(OCTET_STRING, $pdu->security_name())) {
      return $this->_error($msg->error());
   }

   # msgAuthoritativeEngineTime::=INTEGER  
   if (!defined $msg->prepare(INTEGER, $msg_engine_time)) {
      return $this->_error($msg->error());
   }

   # msgAuthoritativeEngineBoots::=INTEGER
   if (!defined $msg->prepare(INTEGER, $msg_engine_boots)) {
      return $this->_error($msg->error());
   }

   # msgAuthoritativeEngineID
   if (!defined $msg->prepare(OCTET_STRING, $this->_engine_id())) {
      return $this->_error($msg->error());
   }

   # UsmSecurityParameters::= SEQUENCE
   if (!defined $msg->prepare(SEQUENCE)) {
      return $this->_error($msg->error());
   }

   # msgSecurityParameters::=OCTET STRING
   if (!defined $msg->prepare(OCTET_STRING, $msg->clear())) {
      return $this->_error($msg->error());
   }

   # Append the PDU
   if (!defined $msg->append($pdu_buffer)) {
      return $this->_error($msg->error());
   }

   # Prepend the msgGlobalData
   if (!defined $msg->prepend($msg_global_data)) {
      return $this->_error($msg->error());
   }

   # version::=INTEGER
   if (!defined $msg->prepare(INTEGER, $this->{_version})) {
      return $this->_error($msg->error());
   }

   # message::=SEQUENCE
   if (!defined $msg->prepare(SEQUENCE)) {
      return $this->_error($msg->error());
   }

   # Apply authentication
   if ($pdu->security_level() > SECURITY_LEVEL_NOAUTHNOPRIV) {
      if (!defined $this->_authenticate_outgoing_msg($msg, $auth_location)) {
         return $this->_error($msg->error());
      }
   }

   # Return the Message
   return $msg;
}

sub process_incoming_msg {
   my ($this, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear();

   return $this->_error('The required Message object is missing') if (@_ < 2);

   # msgSecurityParameters::=OCTET STRING

   my $msg_params = $msg->process(OCTET_STRING);
   return $this->_error($msg->error()) if !defined $msg_params;

   # Need to move the buffer index back to the begining of the data
   # portion of the OCTET STRING that contains the msgSecurityParameters.

   $msg->index($msg->index() - length $msg_params);

   # UsmSecurityParameters::=SEQUENCE
   return $this->_error($msg->error()) if !defined $msg->process(SEQUENCE);

   # msgAuthoritativeEngineID::=OCTET STRING
   my $msg_engine_id;
   if (!defined($msg_engine_id = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error());
   }

   # msgAuthoritativeEngineBoots::=INTEGER (0..2147483647)
   my $msg_engine_boots;
   if (!defined ($msg_engine_boots = $msg->process(INTEGER))) {
      return $this->_error($msg->error());
   }
   if (($msg_engine_boots < 0) || ($msg_engine_boots > 2147483647)) {
      return $this->_error(
         'The msgAuthoritativeEngineBoots value %d is out of range ' .
         '(0..2147483647)', $msg_engine_boots
      );
   }

   # msgAuthoritativeEngineTime::=INTEGER (0..2147483647)
   my $msg_engine_time;
   if (!defined ($msg_engine_time = $msg->process(INTEGER))) {
      return $this->_error($msg->error());
   }
   if (($msg_engine_time < 0) || ($msg_engine_time > 2147483647)) {
      return $this->_error(
         'The msgAuthoritativeEngineTime value %d is out of range ' .
         '(0..2147483647)', $msg_engine_time
      );
   }

   # msgUserName::=OCTET STRING (SIZE(0..32))
   if (!defined $msg->security_name($msg->process(OCTET_STRING))) {
      return $this->_error($msg->error());
   }

   # msgAuthenticationParameters::=OCTET STRING
   my $auth_params;
   if (!defined ($auth_params = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error());
   }

   # We need to zero out the msgAuthenticationParameters in order 
   # to compute the HMAC properly.

   if (my $len = length $auth_params) {
      if ($len != 12) {
         return $this->_error(
            'The msgAuthenticationParameters length of %d is invalid', $len
         );
      }
      substr ${$msg->reference}, ($msg->index() - 12), 12, pack 'x12';
   }

   # msgPrivacyParameters::=OCTET STRING
   my $priv_params;
   if (!defined ($priv_params = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error());
   }

   # Validate the msgAuthoritativeEngineID and msgUserName

   if ($this->{_discovered}) {

      if ($msg_engine_id ne $this->_engine_id()) {
         return $this->_error(
            'The msgAuthoritativeEngineID "%s" was expected, but "%s" was ' .
            'found', unpack('H*', $this->_engine_id()),
            unpack 'H*', $msg_engine_id
         );
      }

      if ($msg->security_name() ne $this->_user_name()) {
         return $this->_error(
            'The msgUserName "%s" was expected, but "%s" was found',
            $this->_user_name(), $msg->security_name()
         );
      }

   } else {

      # Handle authoritativeEngineID discovery
      if (!defined $this->_engine_id_discovery($msg_engine_id)) {
         return $this->_error();
      }

   }

   # Validate the incoming securityLevel

   my $security_level = $msg->security_level();

   if ($security_level > $this->{_security_level}) {
      return $this->_error(
          'The message securityLevel %d is greater than the configured ' .
          'value %d', $security_level, $this->{_security_level}
      );
   }

   if ($security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {

      # Authenticate the message
      if (!defined $this->_authenticate_incoming_msg($msg, $auth_params)) {
         return $this->_error();
      }

      # Synchronize the time
      if (!$this->_synchronize($msg_engine_boots, $msg_engine_time)) {
         return $this->_error();
      }

      # Check for timeliness
      if (!defined $this->_timeliness($msg_engine_boots, $msg_engine_time)) {
         return $this->_error();
      }

      if ($security_level > SECURITY_LEVEL_AUTHNOPRIV) {

         # Validate the msgPrivacyParameters length.

         if (length($priv_params) != 8) {
            return $this->_error(
               'The msgPrivacyParameters length of %d is invalid',
               length $priv_params
            );
         }

         # AES in the USM Section 3.1.2.1 - "The 128-bit IV is
         # obtained as the concatenation of the... ...snmpEngineBoots,
         # ...snmpEngineTime, and a local 64-bit integer.  ...The
         # 64-bit integer must be placed in the msgPrivacyParameters
         # field..."  We must prepend the snmpEngineBoots and
         # snmpEngineTime as received in order to compute the IV.

         if (($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB128)       ||
             ($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_AESCFB192) ||
             ($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_AESCFB256))
         {
            substr $priv_params, 0, 0, pack 'NN', $msg_engine_boots,
                                                  $msg_engine_time;
         }

         # encryptedPDU::=OCTET STRING

         return $this->_decrypt_data($msg,
                                     $priv_params,
                                     $msg->process(OCTET_STRING));

      }

   }

   return TRUE;
}

sub user_name {
   return $_[0]->{_user_name};
}

sub auth_protocol {
   my ($this) = @_;

   if ($this->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
      return $this->{_auth_protocol};
   }

   return AUTH_PROTOCOL_NONE;
}

sub auth_key {
   return $_[0]->{_auth_key};
}

sub priv_protocol {
   my ($this) = @_;

   if ($this->{_security_level} > SECURITY_LEVEL_AUTHNOPRIV) {
      return $this->{_priv_protocol};
   }

   return PRIV_PROTOCOL_NONE;
}

sub priv_key {
   return $_[0]->{_priv_key};
}

sub engine_id {
   return $_[0]->{_engine_id};
}

sub engine_boots {
   goto _engine_boots;
}

sub engine_time {
   goto &_engine_time;
}

sub security_level {
   return $_[0]->{_security_level};
}

use constant {
   security_model => SECURITY_MODEL_USM,  # RFC 3411 - SnmpSecurityModel::=TEXTUAL-CONVENTION
};

sub security_name {
   goto &_user_name;
}

sub discovered {
   my ($this) = @_;

   if ($this->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
      return ($this->{_discovered} && $this->{_synchronized});
   }

   return $this->{_discovered};
}

# [private methods] ----------------------------------------------------------

sub _version {
   my ($this, $version) = @_;

   if ($version != SNMP_VERSION_3) {
      return $this->_error('The SNMP version %s is not supported', $version);
   }

   return $this->{_version} = $version;
}

sub _engine_id {
   my ($this, $engine_id) = @_;

   if (@_ < 2) {
      return $this->{_engine_id};
   }

   if ($engine_id =~  m/^(?:0x)?([A-F0-9]+)$/i) {
       my $eid = pack 'H*', length($1) %  2 ? '0'.$1 : $1;
       my $len = length $eid;
       if ($len < 5 || $len > 32) {
          return $this->_error(
             'The authoritativeEngineID length of %d is out of range (5..32)',
             $len
          );
       }
       $this->{_engine_id} = $eid;
   } else {
      return $this->_error(
          'The authoritativeEngineID "%s" is expected in hexadecimal format',
          $engine_id
      );
   }

   return $this->{_engine_id};
}

sub _user_name {
   my ($this, $user_name) = @_;

   if (@_ == 2) {
      if ($user_name eq q{}) {
         return $this->_error('An empty userName was specified');
      } elsif (length($user_name) > 32) {
         return $this->_error(
            'The userName length of %d is out of range (1..32)',
            length $user_name
         );
      }
      $this->{_user_name} = $user_name;
   }

   # RFC 3414 Section 4 - "Discovery... ...msgUserName of zero-length..."

   return ($this->{_discovered}) ? $this->{_user_name} : q{};
}

sub _snmp_engine_init {
   my ($this) = @_;

   if ($this->{_engine_id} eq q{}) {

      # Initialize our snmpEngineID using the algorithm described 
      # in RFC 3411 - SnmpEngineID::=TEXTUAL-CONVENTION.

      # The first bit is set to one to indicate that the RFC 3411
      # algorithm is being used.  The first fours bytes are to be
      # the agent's SNMP management private enterprise number, but
      # they are set to all zeros. The fifth byte is set to one to
      # indicate that the final four bytes are an IPv4 address.

      if (!defined $ENGINE_ID) {
         $ENGINE_ID = eval {
            require Sys::Hostname;
            pack('H10', '8000000001') . gethostbyname Sys::Hostname::hostname();
         };

         # Fallback in case gethostbyname() or hostname() fail
         if ($@) {
            $ENGINE_ID = pack 'x11H2', '01';
         }
      }

      $this->{_engine_id} = $ENGINE_ID;
   }

   $this->{_engine_boots} = 1;
   $this->{_time_epoc}    = $^T;
   $this->{_synchronized} = TRUE;
   $this->{_discovered}   = TRUE;

   return TRUE;
}

sub _auth_key {
   my ($this, $auth_key) = @_;

   if (@_ == 2) {
      if ($auth_key =~ m/^(?:0x)?([A-F0-9]+)$/i) {
         $this->{_auth_key} = pack 'H*', length($1) % 2 ? '0'.$1 : $1;
         if (!defined $this->_auth_key_validate()) {
            return $this->_error();
         }
      } else {
         return $this->_error(
            'The authKey "%s" is expected in hexadecimal format', $auth_key
         );
      }
   }

   return $this->{_auth_key};
}

sub _auth_password {
   my ($this, $auth_password) = @_;

   if (@_ == 2) {
      if ($auth_password eq q{}) {
         return $this->_error('An empty authentication password was specified');
      }
      $this->{_auth_password} = $auth_password;
   }

   return $this->{_auth_password};
}

sub _auth_protocol {
   my ($this, $proto) = @_;

   state $protocols = {
      '(?:hmac-)?md5(?:-96)?'          => AUTH_PROTOCOL_HMACMD5,
      quotemeta(AUTH_PROTOCOL_HMACMD5) => AUTH_PROTOCOL_HMACMD5,
      '(?:hmac-)?sha(?:-?1|-96)?'      => AUTH_PROTOCOL_HMACSHA,
      quotemeta(AUTH_PROTOCOL_HMACSHA) => AUTH_PROTOCOL_HMACSHA,
   };

   if (@_ < 2) {
      return $this->{_auth_protocol};
   }

   if ($proto eq q{}) {
      return $this->_error('An empty authProtocol was specified');
   }

   for (keys %$protocols) {
      if ($proto =~ /^$_$/i) {
         return $this->{_auth_protocol} = $protocols->{$_};
      }
   }

   return $this->_error('The authProtocol "%s" is unknown', $proto);
}

sub _priv_key {
   my ($this, $priv_key) = @_;

   if (@_ == 2) {
      if ($priv_key =~ m/^(?:0x)?([A-F0-9]+)$/i) {
         $this->{_priv_key} = pack 'H*', length($1) % 2 ? '0'.$1 : $1;
         if (!defined $this->_priv_key_validate()) {
            return $this->_error();
         }
      } else {
         return $this->_error(
            'The privKey "%s" is expected in hexadecimal format', $priv_key
         );
      }
   }

   return $this->{_priv_key};
}

sub _priv_password {
   my ($this, $priv_password) = @_;

   if (@_ == 2) {
      if ($priv_password eq q{}) {
         return $this->_error('An empty privacy password was specified');
      }
      $this->{_priv_password} = $priv_password;
   }

   return $this->{_priv_password};
}


sub _priv_protocol {
   my ($this, $proto) = @_;

   state $protocols = {
      '(?:cbc-)?des'                           => PRIV_PROTOCOL_DES,
      quotemeta(PRIV_PROTOCOL_DES)             => PRIV_PROTOCOL_DES,
      '(?:cbc-)?(?:3|triple-)des(?:-?ede)?'    => PRIV_PROTOCOL_DRAFT_3DESEDE,
      quotemeta(PRIV_PROTOCOL_DRAFT_3DESEDE)   => PRIV_PROTOCOL_DRAFT_3DESEDE,
      '(?:(?:cfb)?128-?)?aes(?:-?128)?'        => PRIV_PROTOCOL_AESCFB128,
      quotemeta(PRIV_PROTOCOL_AESCFB128)       => PRIV_PROTOCOL_AESCFB128,
      quotemeta(PRIV_PROTOCOL_DRAFT_AESCFB128) => PRIV_PROTOCOL_AESCFB128,
      '(?:(?:cfb)?192-?)aes(?:-?128)?'         => PRIV_PROTOCOL_DRAFT_AESCFB192,
      quotemeta(PRIV_PROTOCOL_DRAFT_AESCFB192) => PRIV_PROTOCOL_DRAFT_AESCFB192,
      '(?:(?:cfb)?256-?)aes(?:-?128)?'         => PRIV_PROTOCOL_DRAFT_AESCFB256,
      quotemeta(PRIV_PROTOCOL_DRAFT_AESCFB256) => PRIV_PROTOCOL_DRAFT_AESCFB256,
   };
   
   if (@_ < 2) {
      return $this->{_priv_protocol};
   }

   if ($proto eq q{}) {
      return $this->_error('An empty privProtocol was specified');
   }

   my $priv_proto;

   for (keys %{$protocols}) {
      if ($proto =~ /^$_$/i) {
         $priv_proto = $protocols->{$_};
         last;
      }
   }

   if (!defined $priv_proto) {
      return $this->_error('The privProtocol "%s" is unknown', $proto);
   }

   # Validate the support of the AES cipher algorithm.  Attempt to 
   # load the Crypt::Rijndael module.  If this module is not found, 
   # do not provide support for the AES Cipher Algorithm.

   if (($priv_proto eq PRIV_PROTOCOL_AESCFB128)       ||
       ($priv_proto eq PRIV_PROTOCOL_DRAFT_AESCFB192) ||
       ($priv_proto eq PRIV_PROTOCOL_DRAFT_AESCFB256))
   {
      my ($s, $error) = Class::Load::try_load_module('Crypt::Rijndael');
      if ($error) {
         return $this->_error(
            'Support for privProtocol "%s" is unavailable %s', $proto, $error
         );
      }
   }

   return $this->{_priv_protocol} = $priv_proto;
}

sub _engine_boots {
   return ($_[0]->{_synchronized}) ? $_[0]->{_engine_boots} : 0;
}

sub _engine_time {
   my ($this) = @_;

   return 0 if (!$this->{_synchronized});

   $this->{_engine_time} = time() - $this->{_time_epoc};

   if ($this->{_engine_time} > 2147483647) {
      DEBUG_INFO('snmpEngineTime rollover');
      if (++$this->{_engine_boots} == 2147483647) {
         die 'FATAL: Unable to handle snmpEngineBoots value';
      }
      $this->{_engine_time} -= 2147483647;
      $this->{_time_epoc} = time() - $this->{_engine_time};
      if (!$this->{_authoritative}) {
         $this->{_synchronized} = FALSE;
         return $this->{_latest_engine_time} = 0;
      }
   }

   if ($this->{_engine_time} < 0) {
      die 'FATAL: Unable to handle negative snmpEngineTime value';
   }

   return $this->{_engine_time};
}

sub _security_params {
   my ($this) = @_;

   # Clear any previous error messages
   $this->_error_clear();

   # We must have an usmUserName
   if ($this->{_user_name} eq q{}) {
      return $this->_error('The required userName was not specified');
   }

   # Define the authentication parameters

   if ((defined $this->{_auth_password}) && ($this->{_discovered})) {
      if (!defined $this->{_auth_key}) {
         return $this->_error() if !defined $this->_auth_key_generate();
      }
      $this->{_auth_password} = undef;
   }

   if (defined $this->{_auth_key}) {

      # Validate the key based on the protocol
      if (!defined $this->_auth_key_validate()) {
         return $this->_error('The authKey is invalid');
      }

      # Initialize the authentication data 
      if (!defined $this->_auth_data_init()) {
         return $this->_error('Failed to initialize the authentication data');
      }

      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHNOPRIV;
      }

   }

   # You must have authentication to have privacy

   if (!defined ($this->{_auth_key}) && !defined $this->{_auth_password}) {
      if (defined ($this->{_priv_key}) || defined $this->{_priv_password}) {
         return $this->_error(
            'The securityLevel is unsupported (privacy requires authentication)'
         );
      }
   }

   # Define the privacy parameters

   if ((defined $this->{_priv_password}) && ($this->{_discovered})) {
      if (!defined $this->{_priv_key}) {
         return $this->_error() if !defined $this->_priv_key_generate();
      }
      $this->{_priv_password} = undef;
   }

   if (defined $this->{_priv_key}) {

      # Validate the key based on the protocol
      if (!defined $this->_priv_key_validate()) {
         return $this->_error('The privKey is invalid');
      }

      # Initialize the privacy data 
      if (!defined $this->_priv_data_init()) {
         return $this->_error('Failed to initialize the privacy data');
      }

      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHPRIV;
      }

   }

   DEBUG_INFO('securityLevel = %d', $this->{_security_level});

   return $this->{_security_level};
}

sub _engine_id_discovery {
   my ($this, $engine_id) = @_;

   return TRUE if ($this->{_authoritative});

   DEBUG_INFO('engineID = 0x%s', unpack 'H*', $engine_id || q{});

   if (length($engine_id) < 5 || length($engine_id) > 32) {
      return $this->_error(
         'The msgAuthoritativeEngineID length of %d is out of range (5..32)',
         length $engine_id
      );
   }

   $this->{_engine_id}  = $engine_id;
   $this->{_discovered} = TRUE;

   if (!defined $this->_security_params()) {
      $this->{_discovered} = FALSE;
      return $this->_error();
   }

   return TRUE;
}

sub _synchronize {
   my ($this, $msg_boots, $msg_time) = @_;

   return TRUE if ($this->{_authoritative});
   return TRUE if ($this->{_security_level} < SECURITY_LEVEL_AUTHNOPRIV);

   if (($msg_boots > $this->_engine_boots()) ||
       (($msg_boots == $this->_engine_boots()) &&
        ($msg_time > $this->{_latest_engine_time})))
   {
      DEBUG_INFO(
         'update: engineBoots = %d, engineTime = %d', $msg_boots, $msg_time
      );

      $this->{_engine_boots} = $msg_boots;
      $this->{_latest_engine_time} = $this->{_engine_time} = $msg_time;
      $this->{_time_epoc} = time() - $this->{_engine_time};

      if (!$this->{_synchronized}) {
         $this->{_synchronized} = TRUE;
         if (!defined $this->_security_params()) {
            return ($this->{_synchronized} = FALSE);
         }
      }

      return TRUE;
   }

   DEBUG_INFO(
      'no update: engineBoots = %d, msgBoots = %d; ' .
      'latestTime = %d, msgTime = %d',
      $this->_engine_boots(), $msg_boots,
      $this->{_latest_engine_time}, $msg_time
   );

   return TRUE;
}

sub _timeliness {
   my ($this, $msg_boots, $msg_time) = @_;

   return TRUE if ($this->{_security_level} < SECURITY_LEVEL_AUTHNOPRIV);

   # Retrieve a local copy of our snmpEngineBoots and snmpEngineTime 
   # to avoid the possibilty of using different values in each of 
   # the comparisons.

   my $engine_time  = $this->_engine_time();
   my $engine_boots = $this->_engine_boots();

   if ($engine_boots == 2147483647) {
      $this->{_synchronized} = FALSE;
      return $this->_error('The system is not in the time window');
   }

   if (!$this->{_authoritative}) {

      if ($msg_boots < $engine_boots) {
         return $this->_error('The message is not in the time window');
      }
      if (($msg_boots == $engine_boots) && ($msg_time < ($engine_time - 150))) {
         return $this->_error('The message is not in the time window');
      }

   } else {

      if ($msg_boots != $engine_boots) {
         return $this->_error('The message is not in the time window');
      }
      if (($msg_time < ($engine_time - 150)) ||
          ($msg_time > ($engine_time + 150)))
      {
         return $this->_error('The message is not in the time window');
      }

   }

   return TRUE;
}

sub _authenticate_outgoing_msg {
   my ($this, $msg, $auth_location) = @_;

   if (!$auth_location) {
      return $this->_error(
         'Authentication failure (Unable to set msgAuthenticationParameters)'
      );
   }

   # Set the msgAuthenticationParameters
   substr ${$msg->reference}, -$auth_location, 12, $this->_auth_hmac($msg);

   return TRUE;
}

sub _authenticate_incoming_msg {
   my ($this, $msg, $auth_params) = @_;

   # Authenticate the message
   if ($auth_params ne $this->_auth_hmac($msg)) {
      return $this->_error('Authentication failure');
   }

   DEBUG_INFO('authentication passed');

   return TRUE;
}

sub _auth_hmac {
   my ($this, $msg) = @_;

   return q{} if (!defined($this->{_auth_data}) || !defined $msg);

   return substr
      $this->{_auth_data}->reset()->add(${$msg->reference()})->digest(), 0, 12;
}

sub _auth_data_init {
   my ($this) = @_;

   if (!defined $this->{_auth_key}) {
      return $this->_error('The required authKey is not defined');
   }

   return TRUE if defined $this->{_auth_data};

   if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {

      $this->{_auth_data} =
         Digest::HMAC->new($this->{_auth_key}, 'Digest::MD5');

   } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {

      $this->{_auth_data} =
         Digest::HMAC->new($this->{_auth_key}, 'Digest::SHA');

   } else {
      return $this->_error(
         'The authProtocol "%s" is unknown', $this->{_auth_protocol}
      );

   }

   return TRUE;
}

sub _encrypt_data {
   #my ($this, $msg, $priv_params, $plain) = @_;
   
   return $_[0]->_error('Encryption error (Unknown protocol)')
      unless exists $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} };

   my $subname = '_priv_encrypt_'.
      $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} }->[_SUB_SUFFIX];

   return $_[0]->_error('Encryption error') unless (
      defined $_[1]->prepare(
         OCTET_STRING,
         $_[0]->$subname($_[2], $_[3])
      )
   );

   # Set the PDU buffer equal to the encryptedPDU
   return $_[3] = $_[1]->clear();
}

sub _decrypt_data {
   #my ($this, $msg, $priv_params, $cipher) = @_;

   # Make sure there is data to decrypt.
   if (!defined $_[3]) {
      return $_[0]->_error($_[1]->error() || 'Decryption error (No data)');
   }

   return $_[0]->_error('Decryption error (Unknown protocol)')
      unless exists $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} };

   my $subname = '_priv_decrypt_'.
      $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} }->[_SUB_SUFFIX];

   # Clear the Message buffer
   $_[1]->clear();

   # Put the decrypted data back into the Message buffer
   return $_[0]->_error($_[1]->error()) unless (
      defined $_[1]->prepend(
         $_[0]->$subname($_[2], $_[3])
      )
   );
   return $_[0]->_error($_[1]->error()) unless ($_[1]->length);

   # See if the decrypted data starts with a SEQUENCE 
   # and has a reasonable length.

   my $msglen = $_[1]->process(SEQUENCE);
   return $_[0]->_error('Decryption error')
      unless (defined $msglen && $msglen <= $_[1]->length);
   $_[1]->index(0); # Reset the index

   DEBUG_INFO('privacy passed');

   return TRUE;
}

sub _priv_data_init {
   my ($this) = @_;

   if (!defined $this->{_priv_key}) {
      return $this->_error('The required privKey is not defined');
   }

   return TRUE if defined $this->{_priv_data};

   return $this->_error('The privProtocol "%s" is unknown', $this->{_priv_protocol})
      unless exists $_PROTOCOL_DATA->{ $this->{_priv_protocol} };

   my $subname = '_priv_data_init_'.
      $_PROTOCOL_DATA->{ $this->{_priv_protocol} }->[_SUB_SUFFIX];

   return $this->$subname();
}

sub _priv_data_init_des {
   my ($this) = @_;

   if (!defined $this->{_priv_key}) {
      return $this->_error('The required privKey is not defined');
   }

   # Create the DES object
   $this->{_priv_data}->{des} =
      Crypt::DES->new(substr $this->{_priv_key}, 0, 8);

   # Extract the pre-IV
   $this->{_priv_data}->{pre_iv} = substr $this->{_priv_key}, 8, 8;

   # Initialize the salt
   $this->{_priv_data}->{salt} = int rand ~0;

   return TRUE;
}

sub _priv_encrypt_des {
   #my ($this, $priv_params, $plain) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   # Always pad the plain text data.  "The actual pad value is 
   # irrelevant..." according RFC 3414 Section 8.1.1.2.  However,
   # there are some agents out there that expect "standard block
   # padding" where each of the padding byte(s) are set to the size 
   # of the padding (even for data that is a multiple of block size).

   my $pad = 8 - (length($_[2]) % 8);
   $_[2] .= pack('C', $pad) x $pad;

   # Create and set the salt
   if ($_[0]->{_priv_data}->{salt}++ == ~0) {
      $_[0]->{_priv_data}->{salt} = 0;
   }
   $_[1] = pack 'NN', $_[0]->{_engine_boots}, $_[0]->{_priv_data}->{salt};

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $cipher = q{};

   # Perform Cipher Block Chaining (CBC) 
   while ($_[2] =~ /(.{8})/gs) {
      $cipher .= $iv = $_[0]->{_priv_data}->{des}->encrypt($1 ^ $iv);
   }

   return $cipher;
}

sub _priv_decrypt_des {
   #my ($this, $priv_params, $cipher) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   if (length($_[1]) != 8) {
      return $_[0]->_error(
        'The msgPrivParameters length of %d is invalid', length $_[1]
      );
   }

   if (length($_[2]) % 8) {
      return $_[0]->_error(
         'The DES cipher length is not a multiple of the block size'
      );
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $plain = q{};

   # Perform Cipher Block Chaining (CBC) 
   while ($_[2] =~ /(.{8})/gs) {
      $plain .= $iv ^ $_[0]->{_priv_data}->{des}->decrypt($1);
      $iv = $1;
   }

   return $plain;
}

sub _priv_data_init_3desede {
   my ($this) = @_;

   if (!defined $this->{_priv_key}) {
      return $this->_error('The required privKey is not defined');
   }

   # Create the 3 DES objects

   $this->{_priv_data}->{des1} =
      Crypt::DES->new(substr $this->{_priv_key}, 0, 8);
   $this->{_priv_data}->{des2} =
      Crypt::DES->new(substr $this->{_priv_key}, 8, 8);
   $this->{_priv_data}->{des3} =
      Crypt::DES->new(substr $this->{_priv_key}, 16, 8);

   # Extract the pre-IV
   $this->{_priv_data}->{pre_iv} = substr $this->{_priv_key}, 24, 8;

   # Initialize the salt
   $this->{_priv_data}->{salt} = int rand ~0;

   # Assign a hash algorithm to "bit spread" the salt

   if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {
      $this->{_priv_data}->{hash} = Digest::MD5->new();
   } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {
      $this->{_priv_data}->{hash} = Digest::SHA->new();
   }

   return TRUE;
}

sub _priv_encrypt_3desede {
   #my ($this, $priv_params, $plain) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   # Pad the plain text data using "standard block padding". 
   my $pad = 8 - (length($_[2]) % 8);
   $_[2] .= pack('C', $pad) x $pad;

   # Create and set the salt
   if ($_[0]->{_priv_data}->{salt}++ == ~0) {
      $_[0]->{_priv_data}->{salt} = 0;
   }
   $_[1] = pack 'NN', $_[0]->{_engine_boots}, $_[0]->{_priv_data}->{salt};

   # Draft 3DES-EDE for USM Section 5.1.1.1.2 - "To achieve effective 
   # bit spreading, the complete 8-octet 'salt' value SHOULD be 
   # hashed using the usmUserAuthProtocol."

   if (exists $_[0]->{_priv_data}->{hash}) {
      $_[1] = substr $_[0]->{_priv_data}->{hash}->add($_[1])->digest(), 0, 8;
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $cipher = q{};

   # Perform Cipher Block Chaining (CBC)
   while ($_[2] =~ /(.{8})/gs) {
      $cipher .= $iv =
         $_[0]->{_priv_data}->{des3}->encrypt(
            $_[0]->{_priv_data}->{des2}->decrypt(
               $_[0]->{_priv_data}->{des1}->encrypt($1 ^ $iv)
            )
         );
   }

   return $cipher;
}

sub _priv_decrypt_3desede {
   #my ($this, $priv_params, $cipher) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   if (length($_[1]) != 8) {
      return $_[0]->_error(
        'The msgPrivParameters length of %d is invalid', length $_[1]
      );
   }

   if (length($_[2]) % 8) {
      return $_[0]->_error(
         'The CBC-3DES-EDE cipher length is not a multiple of the block size'
      );
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $plain = q{};

   # Perform Cipher Block Chaining (CBC) 
   while ($_[2] =~ /(.{8})/gs) {
      $plain .=
         $iv ^ $_[0]->{_priv_data}->{des1}->decrypt(
                  $_[0]->{_priv_data}->{des2}->encrypt(
                     $_[0]->{_priv_data}->{des3}->decrypt($1)
                  )
               );
      $iv = $1;
   }

   return $plain;
}

sub _priv_data_init_aescfbxxx {
   my ($this) = @_;

   if (!defined $this->{_priv_key}) {
      return $this->_error('The required privKey is not defined');
   }


   # Create the AES (Rijndael) object with a 128, 192, or 256 bit key.
   # (Avoid a "strict subs" error if Crypt::Rijndael is not loaded.)
   no strict 'subs';
   $this->{_priv_data}->{aes} =
      Crypt::Rijndael->new($this->{_priv_key}, Crypt::Rijndael::MODE_CFB());
   use strict 'subs';

   # Initialize the salt
   $this->{_priv_data}->{salt1} = int rand ~0;
   $this->{_priv_data}->{salt2} = int rand ~0;

   return TRUE;
}

sub _priv_encrypt_aescfbxxx {
#  my ($this, $priv_params, $plain) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   # Validate the plain text length
   my $length = length $_[2];
   if ($length <= 16) {
      return $_[0]->_error(
         'The AES plain text length is not greater than the block size'
      );
   }

   # Create and set the salt
   if ($_[0]->{_priv_data}->{salt1}++ == ~0) {
      $_[0]->{_priv_data}->{salt1} = 0;
      if ($_[0]->{_priv_data}->{salt2}++ == ~0) {
         $_[0]->{_priv_data}->{salt2} = 0;
      }
   }
   $_[1] = pack 'NN', $_[0]->{_priv_data}->{salt2},
                      $_[0]->{_priv_data}->{salt1};

   # AES in the USM Section - Section 3.1.3 "The last ciphertext 
   # block is produced by exclusive-ORing the last plaintext segment 
   # of r bits (r is less or equal to 128) with the segment of the r 
   # most significant bits of the last output block."  

   # This operation is identical to those performed on the previous 
   # blocks except for the fact that the block can be less than the 
   # block size.  We can just pad the last block and operate on it as 
   # usual and then ignore the padding after encrypting.

   $_[2] .= "\000" x (16 - ($length % 16));

   # Create the IV by concatenating "...the generating SNMP engine's 
   # 32-bit snmpEngineBoots, the SNMP engine's 32-bit  snmpEngineTime, 
   # and a local 64-bit integer..." 

   $_[0]->{_priv_data}->{aes}->set_iv(
      pack('NN', $_[0]->{_engine_boots}, $_[0]->{_engine_time}) . $_[1]
   );

   # Let the Crypt::Rijndael module perform 128 bit Cipher Feedback 
   # (CFB) and return the result minus the "internal" padding.

   return substr $_[0]->{_priv_data}->{aes}->encrypt($_[2]), 0, $length;
}

sub _priv_decrypt_aescfbxxx {
#  my ($this, $priv_params, $cipher) = @_;

   if (!defined $_[0]->{_priv_data}) {
      return $_[0]->_error('The required privacy data is not defined');
   }

   # Validate the msgPrivParameters length.  We assume that the
   # msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime
   # have been prepended to the msgPrivParameters to create the
   # required 128 bit IV.

   if (length($_[1]) != 16) {
       return $_[0]->_error(
          'The AES IV length of %d is invalid', length $_[1]
       );
   }

   # Validate the cipher length
   my $length = length $_[2];
   if ($length <= 16) {
      return $_[0]->_error(
         'The AES cipher length is not greater than the block size'
      );
   }

   # AES in the USM Section - Section 3.1.4 "The last ciphertext 
   # block (whose size r is less or equal to 128) is less or equal 
   # to 128) is exclusive-ORed with the segment of the r most 
   # significant bits of the last output block to recover the last 
   # plaintext block of r bits."

   # This operation is identical to those performed on the previous
   # blocks except for the fact that the block can be less than the
   # block size.  We can just pad the last block and operate on it as
   # usual and then ignore the padding after decrypting.

   $_[2] .= "\000" x (16 - ($length % 16));

   # Use the msgPrivParameters as the IV.
   $_[0]->{_priv_data}->{aes}->set_iv($_[1]);

   # Let the Crypt::Rijndael module perform 128 bit Cipher Feedback
   # (CFB) and return the result minus the "internal" padding.

   return substr $_[0]->{_priv_data}->{aes}->decrypt($_[2]), 0, $length;
}

sub _auth_key_generate {
   my ($this) = @_;

   if (!defined($this->{_engine_id}) || !defined $this->{_auth_password}) {
      return $this->_error('Unable to generate the authKey');
   }

   $this->{_auth_key} = $this->_password_localize($this->{_auth_password});

   return $this->{_auth_key};
}

sub _auth_key_validate {
   my ($this) = @_;

   return $_[0]->_error('The authProtocol "%s" is unknown', $this->{_auth_protocol})
      unless exists $_PROTOCOL_DATA->{ $_[0]->{_auth_protocol} };
      
   my $data = $_PROTOCOL_DATA->{ $_[0]->{_auth_protocol} };

   if (length($this->{_auth_key}) != $data->[_KEY_LENGTH]) {
      return $this->_error(
         'The %s authKey length of %d is invalid, expected %d',
         $data->[_KEY_NAME], length($this->{_auth_key}),
         $data->[_KEY_LENGTH]
      );
   }

   return TRUE;
}

sub _priv_key_generate {
   my ($this) = @_;

   if (!defined($this->{_engine_id}) || !defined $this->{_priv_password}) {
      return $this->_error('Unable to generate the privKey');
   }

   $this->{_priv_key} = $this->_password_localize($this->{_priv_password});

   return $this->_error() if !defined $this->{_priv_key};

   if ($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_3DESEDE) {

      # Draft 3DES-EDE for USM Section 2.1 - "To acquire the necessary 
      # number of key bits, the password-to-key algorithm may be chained
      # using its output as further input in order to generate an
      # appropriate number of key bits."

      $this->{_priv_key} .= $this->_password_localize($this->{_priv_key});

   } elsif (($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_AESCFB192) ||
            ($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_AESCFB256))
   {
      # Draft AES in the USM Section 3.1.2.1 - "...if the size of the 
      # localized key is not large enough to generate an encryption 
      # key... ...set Kul = Kul || Hnnn(Kul) where Hnnn is the hash 
      # function for the authentication protocol..."

      my $hnnn;

      if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {
         $hnnn = Digest::MD5->new();
      } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {
         $hnnn = Digest::SHA->new();
      } else {
         return $this->_error(
            'The authProtocol "%s" is unknown', $this->{_auth_protocol}
         );
      }

      $this->{_priv_key} .= $hnnn->add($this->{_priv_key})->digest();

   }

   # Truncate the privKey to the appropriate length.
   return $_[0]->_error('The privProtocol "%s" is unknown', $this->{_priv_protocol})
      unless exists $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} };
      
   $this->{_priv_key} = substr $this->{_priv_key}, 0,
      $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} }->[_KEY_LENGTH];
   return $this->{_priv_key};
}

sub _priv_key_validate {
   my ($this) = @_;

   return $_[0]->_error('The privProtocol "%s" is unknown', $this->{_priv_protocol})
      unless exists $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} };
      
   my $data = $_PROTOCOL_DATA->{ $_[0]->{_priv_protocol} };

   if (length($this->{_priv_key}) != $data->[_KEY_LENGTH]) {
      return $this->_error(
         'The %s privKey length of %d is invalid, expected %d',
         $data->[_KEY_NAME], length($this->{_priv_key}),
         $data->[_KEY_LENGTH]
      );
   }

   if ($this->{_priv_protocol} eq PRIV_PROTOCOL_DRAFT_3DESEDE) {

      # Draft 3DES-EDE for USM Section 5.1.1.1.1 "The checks for difference 
      # and weakness... ...should be performed when the key is assigned.
      # If any of the mandated tests fail, then the whole key MUST be 
      # discarded and an appropriate exception noted."

      if (substr($this->{_priv_key}, 0, 8) eq substr $this->{_priv_key}, 8, 8)
      {
         return $this->_error(
            'The CBC-3DES-EDE privKey is invalid (K1 equals K2)'
         );
      }

      if (substr($this->{_priv_key}, 8, 8) eq substr $this->{_priv_key}, 16, 8)
      {
         return $this->_error(
            'The CBC-3DES-EDE privKey is invalid (K2 equals K3)'
         );
      }

      if (substr($this->{_priv_key}, 0, 8) eq substr $this->{_priv_key}, 16, 8)
      {
         return $this->_error(
            'The CBC-3DES-EDE privKey is invalid (K1 equals K3)'
         );
      }

   }

   return TRUE;
}

sub _password_localize {
   my ($this, $password) = @_;

   state $digests = {
      AUTH_PROTOCOL_HMACMD5() => 'Digest::MD5',
      AUTH_PROTOCOL_HMACSHA() => 'Digest::SHA',
   };
   
   unless (exists $digests->{$this->{_auth_protocol}}) {
      return $this->_error(
         'The authProtocol "%s" is unknown', $this->{_auth_protocol}
      );
   }

   my $digest = $digests->{$this->{_auth_protocol}}->new;

   # Create the initial digest using the password

   my $d = my $pad = $password x ((2048 / length $password) + 1);

   for (my $count = 0; $count < 2**20; $count += 2048) {
      $digest->add(substr $d, 0, 2048, q{});
      $d .= $pad;
   }
   $d = $digest->digest;

   # Localize the key with the authoritativeEngineID

   return $digest->add($d . $this->{_engine_id} . $d)->digest();
}

# ============================================================================
1; # [end Net::SNMPu::Security::USM]

