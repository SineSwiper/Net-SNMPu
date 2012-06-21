package Net::SNMPu::Message::PP;

# ABSTRACT: PurePerl versions of the subs defined in Net::SNMPu::Message::XS

#
# Buffer manipulation methods
#

sub index {
   my ($this, $index) = @_;

   if ((@_ == 2) && ($index >= 0) && ($index <= $this->{_length})) {
      $this->{_index} = $index;
   }

   return $this->{_index};
}

{
   my $process_methods = {
      INTEGER,            \&_process_integer32,
      OCTET_STRING,       \&_process_octet_string,
      NULL,               \&_process_null,
      OBJECT_IDENTIFIER,  \&_process_object_identifier,
      SEQUENCE,           \&_process_sequence,
      IPADDRESS,          \&_process_ipaddress,
      COUNTER,            \&_process_counter,
      GAUGE,              \&_process_gauge,
      TIMETICKS,          \&_process_timeticks,
      OPAQUE,             \&_process_opaque,
      COUNTER64,          \&_process_counter64,
      NOSUCHOBJECT,       \&_process_nosuchobject,
      NOSUCHINSTANCE,     \&_process_nosuchinstance,
      ENDOFMIBVIEW,       \&_process_endofmibview,
      GET_REQUEST,        \&_process_get_request,
      GET_NEXT_REQUEST,   \&_process_get_next_request,
      GET_RESPONSE,       \&_process_get_response,
      SET_REQUEST,        \&_process_set_request,
      TRAP,               \&_process_trap,
      GET_BULK_REQUEST,   \&_process_get_bulk_request,
      INFORM_REQUEST,     \&_process_inform_request,
      SNMPV2_TRAP,        \&_process_v2_trap,
      REPORT,             \&_process_report
   };

   sub process
   {
#     my ($this, $expected, $found) = @_;

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
}

#
# OID Lex functions (previously stored in Net::SNMP)
#

sub oid_base_match {
   my ($this, $base, $oid) = @_;

   defined $base || return FALSE;
   defined $oid  || return FALSE;

   $base =~ s/^\.//o;
   $oid  =~ s/^\.//o;

   $base = pack 'N*', split m/\./, $base;
   $oid  = pack 'N*', split m/\./, $oid;

   return (substr($oid, 0, length $base) eq $base) ? TRUE : FALSE;
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

   return map { $_->[0] }
             sort { $a->[1] cmp $b->[1] }
                map
                {
                   my $oid = $_;
                   $oid =~ s/^\.//;
                   $oid =~ s/ /\.0/g;
                   [$_, pack 'N*', split m/\./, $oid]
                } @_;
}

# [private methods] ----------------------------------------------------------

#
# Basic Encoding Rules (BER) process methods
#

sub _process_length
{
   my ($this) = @_;

   return $this->_error() if defined $this->{_error};

   my $length = $this->_buffer_get(1);

   if (!defined $length) {
      return $this->_error();
   }

   $length = unpack 'C', $length;

   if (!($length & 0x80)) { # "Short" length
      return $length;
   }

   my $byte_cnt = $length & 0x7f;

   if ($byte_cnt == 0) {
      return $this->_error('Indefinite ASN.1 lengths are not supported');
   } elsif ($byte_cnt > 4) {
      return $this->_error(
         'The ASN.1 length is too long (%u bytes)', $byte_cnt
      );
   }

   if (!defined($length = $this->_buffer_get($byte_cnt))) {
      return $this->_error();
   }

   return unpack 'N', ("\000" x (4 - $byte_cnt) . $length);
}

### XXX: This is slightly different than the XS version, which doesn't include
### translation.

sub _process_integer32
{
   my ($this, $type) = @_;

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   # Return an error if the object length is zero?
   if ($length < 1) {
      return $this->_error('The %s length is equal to zero', asn1_itoa($type));
   }

   # Retrieve the whole byte stream outside of the loop.
   return $this->_error() if !defined(my $bytes = $this->_buffer_get($length));

   my @bytes = unpack 'C*', $bytes;
   my $negative = FALSE;
   my $int32 = 0;

   # Validate the length of the Integer32
   if (($length > 5) || (($length > 4) && ($bytes[0] != 0x00))) {
      return $this->_error(
         'The %s length is too long (%u bytes)', asn1_itoa($type), $length
      );
   }

   # If the first bit is set, the Integer32 is negative
   if ($bytes[0] & 0x80) {
      $int32 = -1;
      $negative = TRUE;
   }

   # Build the Integer32
   map { $int32 = (($int32 << 8) | $_) } @bytes;

   if ($negative) {
      if (($type == INTEGER) || (!($this->{_translate} & TRANSLATE_UNSIGNED))) {
         return unpack 'l', pack 'l', $int32;
      } else {
         DEBUG_INFO('translating negative %s value', asn1_itoa($type));
         return unpack 'L', pack 'l', $int32;
      }
   }

   return unpack 'L', pack 'L', $int32;
}

sub _process_octet_string
{
   my ($this, $type) = @_;

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   # Get the string
   return $this->_error() if !defined(my $s = $this->_buffer_get($length));

   # Set the translation mask
   my $mask = ($type == OPAQUE) ? TRANSLATE_OPAQUE : TRANSLATE_OCTET_STRING;

   #
   # Translate based on the definition of a DisplayString in RFC 2579.
   #
   #  DisplayString ::= TEXTUAL-CONVENTION
   # 
   #  - the graphics characters (32-126) are interpreted as
   #    US ASCII
   #  - NUL, LF, CR, BEL, BS, HT, VT and FF have the special
   #    meanings specified in RFC 854
   #  - the sequence 'CR x' for any x other than LF or NUL is
   #    illegal.
   #

   if ($this->{_translate} & $mask) {
      $type = asn1_itoa($type);
      if ($s =~ m{
          #  The values other than NUL, LF, CR, BEL, BS, HT, VT, FF,
          #  and the graphic characters (32-126) trigger translation.
             [\x01-\x06\x0e-\x1f\x7f-\xff]|
          #  The sequence 'CR x' for any x other than LF or NUL
          #  also triggers translation.
             \x0d(?![\x00\x0a])
          }x)
      {
         DEBUG_INFO(
            'translating %s to hexadecimal formatted DisplayString', $type
         );
         return sprintf '0x%s', unpack 'H*', $s;
      } else {
         DEBUG_INFO(
            'not translating %s, all octets are allowed in a DisplayString',
            $type
         );
      }
   }

   return $s;
}

sub _process_object_identifier
{
   my ($this) = @_;

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   # Return an error if the length is equal to zero?
   if ($length < 1) {
      return $this->_error('The OBJECT IDENTIFIER length is equal to zero');
   }

   # Retrieve the whole byte stream (by Niilo Neuvo).

   return $this->_error() if !defined(my $bytes = $this->_buffer_get($length));

   my @oid = ( 0, eval { unpack 'w129', $bytes } );

   # RFC 2578 Section 3.5 - "...there are at most 128 sub-identifiers in
   # a value, and each sub-identifier has a maximum value of 2^32-1..."

   if ($@ || (grep { $_ > 4294967295; } @oid)) {
      return $this->_error(
         'The OBJECT IDENTIFIER contains a sub-identifier which is out of ' .
         'range (0..4294967295)'
      );
   }

   if (@oid > 128) {
      return $this->_error(
         'The OBJECT IDENTIFIER contains more than the maximum of 128 ' .
         'sub-identifiers allowed'
      );
   }

   # The first two sub-identifiers are encoded into the first identifier
   # using the the equation: subid = ((first * 40) + second).

   if ($oid[1] == 0x2b) {   # Handle the most common case
      $oid[0] = 1;          # first [iso(1).org(3)]
      $oid[1] = 3;
   } elsif ($oid[1] < 40) {
      $oid[0] = 0;
   } elsif ($oid[1] < 80) {
      $oid[0] = 1;
      $oid[1] -= 40;
   } else {
      $oid[0] = 2;
      $oid[1] -= 80;
   }

   # Return the OID in dotted notation (optionally with a 
   # leading dot if one was passed to the prepare routine).

   if ($this->{_leading_dot}) {
      DEBUG_INFO('adding leading dot');
      unshift @oid, q{};
   }

   return join q{.}, @oid;
}

sub _process_sequence
{
   # Return the length, instead of the value
   goto &_process_length;
}

sub _process_ipaddress
{
   my ($this) = @_;

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   if ($length != 4) {
      return $this->_error('The IpAddress length of %d is invalid', $length);
   }

   if (defined(my $ipaddress = $this->_buffer_get(4))) {
      return sprintf '%vd', $ipaddress;
   }

   return $this->_error();
}

sub _process_counter
{
   goto &_process_integer32;
}

sub _process_gauge
{
   goto &_process_integer32;
}

### XXX: This is slightly different than the XS version, which doesn't include
### translation.

sub _process_timeticks
{
   my ($this) = @_;

   if (defined(my $ticks = $this->_process_integer32(TIMETICKS))) {
      if ($this->{_translate} & TRANSLATE_TIMETICKS) {
         DEBUG_INFO('translating %u TimeTicks to time', $ticks);
         return asn1_ticks_to_time($ticks);
      } else {
         return $ticks;
      }
   }

   return $this->_error();
}

sub _process_opaque
{
   goto &_process_octet_string;
}

sub _process_counter64
{
   my ($this, $type) = @_;

   # Verify the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('The Counter64 type is not supported in SNMPv1');
   }

   # Decode the length
   return $this->_error() if !defined(my $length = $this->_process_length());

   # Return an error if the object length is zero?
   if ($length < 1) {
      return $this->_error('The Counter64 length is equal to zero');
   }

   # Retrieve the whole byte stream outside of the loop.
   return $this->_error() if !defined(my $bytes = $this->_buffer_get($length));

   my @bytes = unpack 'C*', $bytes;
   my $negative = FALSE;

   # Validate the length of the Counter64
   if (($length > 9) || (($length > 8) && ($bytes[0] != 0x00))) {
      return $_[0]->_error(
          'The Counter64 length is too long (%u bytes)', $length
      );
   }

   # If the first bit is set, the integer is negative
   if ($bytes[0] & 0x80) {
      $bytes[0] ^= 0xff;
      $negative = TRUE;
   }

   # Build the Counter64
   my $int64 = Math::BigInt->new(shift @bytes);
   map {
      if ($negative) { $_ ^= 0xff; }
      $int64 *= 256;
      $int64 += $_;
   } @bytes;

   # If the value is negative the other end incorrectly encoded
   # the Counter64 since it should always be a positive value.

   if ($negative) {
      $int64 = Math::BigInt->new('-1') - $int64;
      if ($this->{_translate} & TRANSLATE_UNSIGNED) {
         DEBUG_INFO('translating negative Counter64 value');
         $int64 += Math::BigInt->new('18446744073709551616');
      }
   }

   # Perl 5.6.0 (force to string or substitution does not work).
   $int64 .= q{};

   # Remove the plus sign (or should we leave it to imply Math::BigInt?)
   $int64 =~ s/^\+//;

   return $int64;
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

sub _buffer_get {
   my ($this, $requested) = @_;

   return $this->_error() if defined $this->{_error};

   # Return the number of bytes requested at the current index or 
   # clear and return the whole buffer if no argument is passed. 

   if (@_ == 2) {

      if (($this->{_index} += $requested) > $this->{_length}) {
         $this->{_index} -= $requested;
         if ($this->{_length} >= $this->max_msg_size()) {
            return $this->_error(
               'The message size exceeded the buffer maxMsgSize of %d',
               $this->max_msg_size()
            );
         }
         return $this->_error('Unexpected end of message buffer');
      }

      return substr $this->{_buffer}, $this->{_index} - $requested, $requested;
   }

   # Always reset the index when the buffer is modified
   $this->{_index} = 0;

   # Update our length to 0, the whole buffer is about to be cleared.
   $this->{_length} = 0;

   return substr $this->{_buffer}, 0, CORE::length($this->{_buffer}), q{};
}

# ============================================================================
1; # [end Net::SNMPu::Message::PP]
