require "./spec_helper"

# RFC 4648 §10.
RFC4648_VECTORS = {
  ""       => "",
  "f"      => "MY======",
  "fo"     => "MZXQ====",
  "foo"    => "MZXW6===",
  "foob"   => "MZXW6YQ=",
  "fooba"  => "MZXW6YTB",
  "foobar" => "MZXW6YTBOI======",
}

describe TOTP::Base32 do
  describe "RFC 4648 test vectors" do
    RFC4648_VECTORS.each do |plain, encoded|
      it "encodes #{plain.inspect}" do
        TOTP::Base32.encode(plain.to_slice).should eq(encoded)
      end

      it "decodes #{encoded.inspect}" do
        String.new(TOTP::Base32.decode(encoded)).should eq(plain)
      end
    end
  end

  describe "round-trip" do
    it "survives arbitrary bytes" do
      100.times do
        data = Random::Secure.random_bytes(Random.rand(1..64))
        TOTP::Base32.decode(TOTP::Base32.encode(data)).should eq(data)
      end
    end
  end

  describe "what people actually type" do
    it "accepts a secret without padding" do
      String.new(TOTP::Base32.decode("MZXW6YTBOI")).should eq("foobar")
    end

    it "accepts lowercase" do
      String.new(TOTP::Base32.decode("mzxw6ytboi")).should eq("foobar")
    end

    it "accepts the spacing authenticator apps display" do
      String.new(TOTP::Base32.decode("MZXW 6YTB OI")).should eq("foobar")
    end

    it "accepts hyphens" do
      String.new(TOTP::Base32.decode("MZXW-6YTB-OI")).should eq("foobar")
    end

    it "groups a secret for manual entry" do
      TOTP::Base32.format_for_display("MZXW6YTBOI======").should eq("MZXW 6YTB OI")
    end
  end

  describe "rejection" do
    # 0, 1, 8 and 9 are absent from the alphabet precisely because they are
    # confusable with O, I and B.
    it "refuses a character outside the alphabet" do
      expect_raises(TOTP::DecodeError, /not a base32 character/) do
        TOTP::Base32.decode("MZXW0YTB")
      end
    end

    # Silently returning a shorter secret would mean generating codes that
    # never match, with nothing to explain why.
    it "refuses a length that cannot encode whole bytes" do
      # 9 characters is 45 bits: 5 bytes and 5 bits left over.
      expect_raises(TOTP::DecodeError, /truncated or corrupt/) do
        TOTP::Base32.decode("MZXW6YTBO")
      end
    end

    it "refuses non-zero padding bits" do
      # 5 characters is a legal length, but the trailing bit must be zero.
      expect_raises(TOTP::DecodeError, /truncated or corrupt/) do
        TOTP::Base32.decode("MZXWB")
      end
    end

    it "accepts a legal unpadded length" do
      # 5 characters encode exactly 3 bytes; this one is well-formed.
      TOTP::Base32.decode("MZXWA").size.should eq(3)
    end
  end
end
