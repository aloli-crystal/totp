require "./spec_helper"

# The published test vectors are the only judge that matters here: a one-time
# password implementation that agrees with itself but not with the RFC agrees
# with no authenticator app either.

describe TOTP::HOTP do
  # RFC 4226, Appendix D.
  describe "RFC 4226 Appendix D" do
    {
      0 => "755224", 1 => "287082", 2 => "359152", 3 => "969429", 4 => "338314",
      5 => "254676", 6 => "287922", 7 => "162583", 8 => "399871", 9 => "520489",
    }.each do |counter, expected|
      it "counter #{counter} yields #{expected}" do
        TOTP::HOTP.generate(RFC_SECRET_SHA1, counter.to_u64).should eq(expected)
      end
    end
  end
end

describe TOTP::Authenticator do
  # RFC 6238, Appendix B. T0 = 0, step = 30 s, 8 digits.
  describe "RFC 6238 Appendix B" do
    {
               59_i64 => {"94287082", "46119246", "90693936"},
       1111111109_i64 => {"07081804", "68084774", "25091201"},
       1111111111_i64 => {"14050471", "67062674", "99943326"},
       1234567890_i64 => {"89005924", "91819424", "93441116"},
       2000000000_i64 => {"69279037", "90698825", "38618901"},
      20000000000_i64 => {"65353130", "77737706", "47863826"},
    }.each do |unix, (sha1, sha256, sha512)|
      time = Time.unix(unix)

      it "SHA-1 at #{unix}" do
        auth = TOTP::Authenticator.new(RFC_SECRET_SHA1, digits: 8, algorithm: TOTP::Algorithm::SHA1)
        auth.at(time).should eq(sha1)
      end

      it "SHA-256 at #{unix}" do
        auth = TOTP::Authenticator.new(RFC_SECRET_SHA256, digits: 8, algorithm: TOTP::Algorithm::SHA256)
        auth.at(time).should eq(sha256)
      end

      it "SHA-512 at #{unix}" do
        auth = TOTP::Authenticator.new(RFC_SECRET_SHA512, digits: 8, algorithm: TOTP::Algorithm::SHA512)
        auth.at(time).should eq(sha512)
      end
    end
  end
end
