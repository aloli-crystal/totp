require "random/secure"

require "./totp/version"
require "./totp/errors"
require "./totp/base32"
require "./totp/hotp"
require "./totp/authenticator"

# TOTP and HOTP — RFC 6238 and RFC 4226.
#
# The second factor of a password. Note that it is *not* needed alongside a
# passkey: an authenticator that performs user verification has already proved
# possession and knowledge in one gesture, and adding a code to that costs
# ergonomics without buying security.
#
# ```
# secret = TOTP.generate_secret
# auth = TOTP::Authenticator.new(secret)
#
# # Show this as a QR code at enrolment, and store `secret` against the user.
# auth.provisioning_uri(account: "alice@example.com", issuer: "Partiduo")
#
# # At sign-in. Store the returned counter and pass it back as `after` next
# # time, or the code stays replayable for the whole drift window.
# if counter = auth.verify(submitted_code, after: user.last_otp_counter)
#   user.last_otp_counter = counter
# end
# ```
module TOTP
  # RFC 4226 §4 requires at least 128 bits of secret and recommends 160 —
  # which is also the output size of SHA-1, the algorithm nearly every
  # authenticator app actually uses.
  DEFAULT_SECRET_SIZE = 20
  MINIMUM_SECRET_SIZE = 16

  def self.generate_secret(size : Int32 = DEFAULT_SECRET_SIZE) : Bytes
    if size < MINIMUM_SECRET_SIZE
      raise ConfigurationError.new(
        "RFC 4226 requires at least #{MINIMUM_SECRET_SIZE} bytes of secret, asked for #{size}"
      )
    end
    Random::Secure.random_bytes(size)
  end

  # A fresh secret, already base32-encoded for display or storage.
  def self.generate_secret_base32(size : Int32 = DEFAULT_SECRET_SIZE) : String
    Base32.encode(generate_secret(size))
  end
end
