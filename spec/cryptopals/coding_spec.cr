require "../spec_helper"

describe Cryptopals::Coding do
  it "#hex_to_bytes" do
    Cryptopals::Coding.hex_to_bytes("2a3b").should eq(Bytes[0x2a, 0x3b])
  end

  it "#hex_to_bytes raises unless hexstring is passed" do
    expect_raises(Exception, Cryptopals::Coding::MUST_BE_HEX) do
      Cryptopals::Coding.hex_to_bytes("hi there")
    end
  end

  it "#hex_to_base64" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    Cryptopals::Coding.hex_to_base64(hex).should eq(base64)
  end

  it "#bytes_to_base64" do    
    Cryptopals::Coding.bytes_to_base64(Bytes[0x2a_u8, 0x3b_u8]).should eq("Kjs=")
  end

  it "#base64_to_bytes" do    
    Cryptopals::Coding.base64_to_bytes("Kjs=").should eq(Bytes[0x2a_u8, 0x3b_u8])
  end

  it "#bytes_to_hex" do    
    Cryptopals::Coding.bytes_to_hex(Bytes[0x2a_u8, 0x3b_u8]).should eq("2a3b")
  end
end
