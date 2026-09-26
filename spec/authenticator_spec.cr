require "./spec_helper"

describe TOTP::Authenticator do
  describe "verification" do
    it "accepts the current code and reports the counter it matched" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)

      auth.verify(auth.at(time), time).should eq(auth.counter_at(time))
    end

    it "rejects a wrong code" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      auth.verify("000000", Time.unix(1111111111)).should be_nil
    end

    it "rejects a code of the wrong length without consulting the secret" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      auth.verify("12345").should be_nil
      auth.verify("1234567").should be_nil
      auth.verify("").should be_nil
    end

    it "tolerates the spacing a user pastes in" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)
      code = auth.at(time)

      auth.verify(" #{code[0, 3]} #{code[3, 3]} ", time).should_not be_nil
    end
  end

  describe "clock drift" do
    it "accepts the previous and next step by default" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)

      auth.verify(auth.at(time - 30.seconds), time).should_not be_nil
      auth.verify(auth.at(time + 30.seconds), time).should_not be_nil
    end

    it "refuses two steps away by default" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)

      auth.verify(auth.at(time - 60.seconds), time).should be_nil
      auth.verify(auth.at(time + 60.seconds), time).should be_nil
    end

    it "accepts nothing but the current step when drift is zero" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)

      auth.verify(auth.at(time), time, drift: 0).should_not be_nil
      auth.verify(auth.at(time - 30.seconds), time, drift: 0).should be_nil
    end

    it "refuses a negative drift" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      expect_raises(TOTP::ConfigurationError, /drift cannot be negative/) do
        auth.verify("123456", drift: -1)
      end
    end
  end

  # A one-time password is only one-time if the caller stores the counter and
  # refuses anything at or below it. Without `after`, a code stays usable for
  # the whole drift window.
  describe "replay" do
    it "refuses a counter already used" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)
      code = auth.at(time)

      used = auth.verify(code, time)
      used.should_not be_nil

      auth.verify(code, time, after: used).should be_nil
    end

    it "refuses an older counter still inside the drift window" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)
      current = auth.counter_at(time)

      auth.verify(auth.at(time - 30.seconds), time, after: current).should be_nil
    end

    it "still accepts a later counter" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      time = Time.unix(1111111111)
      previous = auth.counter_at(time) - 1

      auth.verify(auth.at(time), time, after: previous).should_not be_nil
    end
  end

  describe "timing" do
    it "reports how long the current code lasts" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      auth.seconds_remaining(Time.unix(1111111110)).should eq(30)
      auth.seconds_remaining(Time.unix(1111111111)).should eq(29)
      auth.seconds_remaining(Time.unix(1111111139)).should eq(1)
    end

    it "changes code at each step boundary" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      auth.at(Time.unix(1111111110)).should eq(auth.at(Time.unix(1111111139)))
      auth.at(Time.unix(1111111110)).should_not eq(auth.at(Time.unix(1111111140)))
    end
  end

  describe "provisioning URI" do
    it "builds a URI an authenticator app can scan" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      uri = auth.provisioning_uri(account: "alice@example.com", issuer: "Partiduo")

      uri.should start_with("otpauth://totp/Partiduo:alice%40example.com?")
      uri.should contain("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
      uri.should contain("issuer=Partiduo")
      uri.should contain("algorithm=SHA1")
      uri.should contain("digits=6")
      uri.should contain("period=30")
    end

    # `+` would be read literally by a strict URI parser: the issuer would
    # arrive as "ACME+Co".
    it "percent-encodes a space in the issuer rather than using +" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      uri = auth.provisioning_uri(account: "alice@example.com", issuer: "ACME Co")

      uri.should contain("issuer=ACME%20Co")
      uri.should start_with("otpauth://totp/ACME%20Co:alice%40example.com?")
      uri.should_not contain("+")
    end

    it "omits the issuer when there is none" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      uri = auth.provisioning_uri(account: "alice")

      uri.should start_with("otpauth://totp/alice?")
      uri.should_not contain("issuer=")
    end

    it "strips padding from the secret, as apps expect" do
      auth = TOTP::Authenticator.new("f".to_slice)
      auth.provisioning_uri(account: "a").should contain("secret=MY&")
    end

    # A colon separates issuer from account in the label; letting one through
    # would silently change which account the code belongs to.
    it "refuses a colon in the account or the issuer" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      expect_raises(ArgumentError, /must not contain/) do
        auth.provisioning_uri(account: "a:b")
      end
      expect_raises(ArgumentError, /must not contain/) do
        auth.provisioning_uri(account: "a", issuer: "x:y")
      end
    end

    it "refuses an empty account" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      expect_raises(ArgumentError, /must not be empty/) do
        auth.provisioning_uri(account: "")
      end
    end
  end

  describe "construction" do
    it "round-trips a base32 secret" do
      auth = TOTP::Authenticator.new(RFC_SECRET_SHA1)
      again = TOTP::Authenticator.from_base32(auth.secret_base32)

      again.secret.should eq(auth.secret)
      again.at(Time.unix(59)).should eq(auth.at(Time.unix(59)))
    end

    it "refuses an empty secret" do
      expect_raises(TOTP::ConfigurationError, /must not be empty/) do
        TOTP::Authenticator.new(Bytes.empty)
      end
    end

    it "refuses a non-positive period" do
      expect_raises(TOTP::ConfigurationError, /period must be positive/) do
        TOTP::Authenticator.new(RFC_SECRET_SHA1, period: 0)
      end
    end

    it "refuses a digit count outside RFC 4226's range" do
      expect_raises(TOTP::ConfigurationError, /between 6 and 8/) do
        TOTP::Authenticator.new(RFC_SECRET_SHA1, digits: 5)
      end
      expect_raises(TOTP::ConfigurationError, /between 6 and 8/) do
        TOTP::Authenticator.new(RFC_SECRET_SHA1, digits: 9)
      end
    end
  end
end

describe TOTP do
  describe ".generate_secret" do
    it "produces 20 unpredictable bytes by default" do
      a = TOTP.generate_secret
      a.size.should eq(20)
      a.should_not eq(TOTP.generate_secret)
    end

    it "refuses a secret below RFC 4226's minimum" do
      expect_raises(TOTP::ConfigurationError, /at least 16 bytes/) do
        TOTP.generate_secret(8)
      end
    end

    it "produces a base32 secret ready for display" do
      secret = TOTP.generate_secret_base32
      TOTP::Base32.decode(secret).size.should eq(20)
    end
  end

  describe TOTP::Algorithm do
    it "names itself as a provisioning URI does" do
      TOTP::Algorithm::SHA1.uri_name.should eq("SHA1")
      TOTP::Algorithm::SHA512.uri_name.should eq("SHA512")
    end

    it "parses a name from a URI" do
      TOTP::Algorithm.from_uri_name("sha256").should eq(TOTP::Algorithm::SHA256)
      expect_raises(TOTP::ConfigurationError, /unknown algorithm/) do
        TOTP::Algorithm.from_uri_name("md5")
      end
    end
  end
end
