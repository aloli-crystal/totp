module TOTP
  # Base class for every error this shard raises.
  class Error < Exception
  end

  # Raised when a base32 string cannot be decoded.
  class DecodeError < Error
  end

  # Raised when a parameter would produce codes no authenticator can use.
  class ConfigurationError < Error
  end
end
