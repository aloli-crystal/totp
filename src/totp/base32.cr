require "./errors"

module TOTP
  # Base32 as specified by RFC 4648 §6 — the encoding every authenticator app
  # expects a shared secret in.
  #
  # Encoding is strict RFC 4648, padded. Decoding is deliberately forgiving of
  # what humans and QR codes actually produce — lowercase, spaces, hyphens,
  # missing padding — while refusing any character outside the alphabet. A
  # secret typed by hand with the spacing an app displayed must work; a secret
  # with a stray character must not silently decode to something else.
  module Base32
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    PADDING  = '='

    # Decoding table: value for each ASCII byte, -1 when not in the alphabet.
    # Lowercase maps to the same values — a secret is often retyped by hand.
    private DECODE_TABLE = begin
      table = StaticArray(Int8, 256).new(-1_i8)
      ALPHABET.each_char_with_index do |char, index|
        table[char.ord] = index.to_i8
        table[char.downcase.ord] = index.to_i8
      end
      table
    end

    def self.encode(data : Bytes) : String
      return "" if data.empty?

      String.build do |io|
        buffer = 0_u32
        bits = 0

        data.each do |byte|
          buffer = (buffer << 8) | byte
          bits += 8
          while bits >= 5
            bits -= 5
            io << ALPHABET[(buffer >> bits) & 0x1f]
          end
        end

        if bits > 0
          io << ALPHABET[(buffer << (5 - bits)) & 0x1f]
        end

        # Pad to a multiple of 8 characters.
        remainder = (data.size * 8 + 4) // 5 % 8
        (8 - remainder).times { io << PADDING } unless remainder.zero?
      end
    end

    def self.decode(text : String) : Bytes
      buffer = 0_u32
      bits = 0
      output = IO::Memory.new

      text.each_char do |char|
        # Separators authenticator apps and users insert for readability.
        next if char.ascii_whitespace? || char == '-' || char == PADDING

        code = char.ord
        value = code < 256 ? DECODE_TABLE[code] : -1_i8
        if value < 0
          raise DecodeError.new("#{char.inspect} is not a base32 character")
        end

        buffer = (buffer << 5) | value.to_u32
        bits += 5
        if bits >= 8
          bits -= 8
          output.write_byte(((buffer >> bits) & 0xff).to_u8)
        end
      end

      # Whatever is left must be zero padding bits. Anything else means the
      # string was truncated mid-byte, and the secret it yields would be wrong.
      unless bits < 5 && (buffer & ((1_u32 << bits) - 1)).zero?
        raise DecodeError.new("base32 string ends mid-byte: it is truncated or corrupt")
      end

      output.to_slice
    end

    # Group a secret in blocks of four, the way authenticator apps display one
    # for manual entry.
    def self.format_for_display(text : String, group : Int32 = 4) : String
      raise ArgumentError.new("group size must be positive") unless group > 0
      text.delete(PADDING).chars.each_slice(group).map(&.join).join(' ')
    end
  end
end
