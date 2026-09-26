require "spec"
require "../src/totp"

# RFC 4226 Appendix D and RFC 6238 Appendix B share this ASCII secret.
RFC_SECRET_SHA1 = "12345678901234567890".to_slice

# RFC 6238 Appendix B uses a longer secret per algorithm, obtained by
# repeating the same digits.
RFC_SECRET_SHA256 = "12345678901234567890123456789012".to_slice
RFC_SECRET_SHA512 = "1234567890123456789012345678901234567890123456789012345678901234".to_slice
