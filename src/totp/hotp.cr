require "openssl/hmac"
require "./errors"

module TOTP
  # Hash algorithms an authenticator may be configured with.
  #
  # SHA-1 is the default and, in practice, the only portable choice: Google
  # Authenticator and most of its clones ignore the `algorithm` parameter in a
  # provisioning URI and always compute SHA-1. Choosing SHA-256 or SHA-512
  # means committing to apps that honour it.
  enum Algorithm
    SHA1
    SHA256
    SHA512

    def to_openssl : OpenSSL::Algorithm
      case self
      in SHA1   then OpenSSL::Algorithm::SHA1
      in SHA256 then OpenSSL::Algorithm::SHA256
      in SHA512 then OpenSSL::Algorithm::SHA512
      end
    end

    # The spelling used in an `otpauth://` URI.
    def uri_name : String
      case self
      in SHA1   then "SHA1"
      in SHA256 then "SHA256"
      in SHA512 then "SHA512"
      end
    end

    def self.from_uri_name(name : String) : Algorithm
      case name.upcase
      when "SHA1"   then SHA1
      when "SHA256" then SHA256
      when "SHA512" then SHA512
      else
        raise ConfigurationError.new("unknown algorithm #{name.inspect}")
      end
    end
  end

  # HMAC-based one-time passwords, RFC 4226.
  #
  # The counter-based half of the family. `TOTP::Authenticator` derives the
  # counter from the clock and delegates here.
  module HOTP
    # RFC 4226 §5.3 allows 6 to 8 digits; below 6 the code is guessable.
    DIGIT_RANGE = 6..8

    def self.generate(secret : Bytes, counter : UInt64, digits : Int32 = 6,
                      algorithm : Algorithm = Algorithm::SHA1) : String
      unless DIGIT_RANGE.includes?(digits)
        raise ConfigurationError.new("digits must be between #{DIGIT_RANGE.begin} and #{DIGIT_RANGE.end}")
      end
      raise ConfigurationError.new("the secret must not be empty") if secret.empty?

      # The counter is hashed as an 8-byte big-endian integer.
      message = Bytes.new(8)
      8.times { |i| message[i] = ((counter >> ((7 - i) * 8)) & 0xff).to_u8 }

      digest = OpenSSL::HMAC.digest(algorithm.to_openssl, secret, message)

      # Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte
      # picks where to read four bytes from, and the top bit is masked off so
      # the result is positive regardless of the platform's signedness.
      offset = (digest[digest.size - 1] & 0x0f).to_i
      binary = ((digest[offset] & 0x7f).to_u32 << 24) |
               (digest[offset + 1].to_u32 << 16) |
               (digest[offset + 2].to_u32 << 8) |
               digest[offset + 3].to_u32

      modulus = 10_u32 ** digits
      (binary % modulus).to_s.rjust(digits, '0')
    end
  end
end
