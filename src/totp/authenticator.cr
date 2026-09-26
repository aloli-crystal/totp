require "crypto/subtle"
require "uri"
require "./errors"
require "./base32"
require "./hotp"

module TOTP
  # Time-based one-time passwords, RFC 6238.
  #
  # ```
  # secret = TOTP.generate_secret
  # auth = TOTP::Authenticator.new(secret)
  #
  # auth.provisioning_uri(account: "alice@example.com", issuer: "Partiduo")
  # auth.at               # => "492039"
  # auth.verify("492039") # => the counter that matched, or nil
  # ```
  class Authenticator
    DEFAULT_PERIOD = 30
    DEFAULT_DIGITS =  6

    getter secret : Bytes
    getter digits : Int32
    getter period : Int32
    getter algorithm : Algorithm

    def initialize(@secret : Bytes, @digits : Int32 = DEFAULT_DIGITS,
                   @period : Int32 = DEFAULT_PERIOD, @algorithm : Algorithm = Algorithm::SHA1)
      raise ConfigurationError.new("the secret must not be empty") if @secret.empty?
      raise ConfigurationError.new("the period must be positive") unless @period > 0
      unless HOTP::DIGIT_RANGE.includes?(@digits)
        raise ConfigurationError.new("digits must be between #{HOTP::DIGIT_RANGE.begin} and #{HOTP::DIGIT_RANGE.end}")
      end
    end

    # Build from a base32 secret, as an authenticator app stores it.
    def self.from_base32(secret : String, digits : Int32 = DEFAULT_DIGITS,
                         period : Int32 = DEFAULT_PERIOD,
                         algorithm : Algorithm = Algorithm::SHA1) : Authenticator
      new(Base32.decode(secret), digits, period, algorithm)
    end

    def secret_base32 : String
      Base32.encode(@secret)
    end

    # The counter covering `time` — RFC 6238's T.
    def counter_at(time : Time = Time.utc) : UInt64
      unix = time.to_unix
      raise ConfigurationError.new("times before the Unix epoch are not supported") if unix < 0
      (unix // @period).to_u64
    end

    # The code valid at `time`.
    def at(time : Time = Time.utc) : String
      HOTP.generate(@secret, counter_at(time), @digits, @algorithm)
    end

    # Seconds until the current code expires — for a countdown in the UI.
    def seconds_remaining(time : Time = Time.utc) : Int32
      @period - (time.to_unix % @period).to_i
    end

    # Verify a code, returning the counter it matched, or `nil`.
    #
    # The counter is returned rather than a boolean for a reason: a one-time
    # password is only one-time if the caller **stores the counter and refuses
    # anything at or below it next time**. Pass that stored value as `after`
    # and this method enforces it; ignore the return value and a code stays
    # replayable for the whole drift window.
    #
    # `drift` accepts codes that many steps either side of now, covering clock
    # skew between the server and the user's device. One step — 30 seconds —
    # is the usual compromise; widening it widens the window an intercepted
    # code stays usable in.
    def verify(code : String, time : Time = Time.utc, drift : Int32 = 1,
               after : UInt64? = nil) : UInt64?
      raise ConfigurationError.new("drift cannot be negative") if drift < 0

      candidate = code.strip.delete(' ')
      return unless candidate.size == @digits

      current = counter_at(time)
      matched = nil

      # Every candidate is checked, and the comparison is constant time, so
      # neither the answer nor how long it took reveals which step matched.
      (-drift..drift).each do |offset|
        counter = current.to_i64 + offset
        next if counter < 0

        counter = counter.to_u64
        expected = HOTP.generate(@secret, counter, @digits, @algorithm)
        matched = counter if Crypto::Subtle.constant_time_compare(expected, candidate)
      end

      return if matched.nil?
      return if after && matched <= after
      matched
    end

    # An `otpauth://` URI, the payload of the QR code a user scans.
    #
    # `issuer` is repeated in the label and as a parameter: older apps read one,
    # newer ones the other.
    def provisioning_uri(account : String, issuer : String? = nil) : String
      raise ArgumentError.new("the account must not be empty") if account.empty?
      if account.includes?(':') || (issuer && issuer.includes?(':'))
        raise ArgumentError.new("account and issuer must not contain ':' — it separates them in the label")
      end

      # Each half is encoded separately so the separating colon stays literal:
      # percent-encoding it would stop apps splitting issuer from account.
      label = if issuer
                "#{URI.encode_path_segment(issuer)}:#{URI.encode_path_segment(account)}"
              else
                URI.encode_path_segment(account)
              end

      # Percent-encoded, not form-encoded: a space must come out as `%20`.
      # `URI::Params` would write `+`, which a strict URI reader takes
      # literally — an issuer named "ACME Co" would arrive as "ACME+Co".
      pairs = [] of String
      pairs << "secret=#{secret_base32.delete(Base32::PADDING)}"
      pairs << "issuer=#{URI.encode_www_form(issuer, space_to_plus: false)}" if issuer
      pairs << "algorithm=#{@algorithm.uri_name}"
      pairs << "digits=#{@digits}"
      pairs << "period=#{@period}"

      "otpauth://totp/#{label}?#{pairs.join('&')}"
    end
  end
end
