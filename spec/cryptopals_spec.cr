require "./spec_helper"

describe Cryptopals do
  it "Set 1, Challenge 1: Convert hex to base64" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    Cryptopals::Coding.hex_to_base64(hex).should eq(base64)
  end

  it "Set 1, Challenge 2: Fixed XOR" do
    hex1 = "1c0111001f010100061a024b53535009181c"
    hex2 = "686974207468652062756c6c277320657965"
    hex3 = "746865206b696420646f6e277420706c6179"

    bytes1 = Cryptopals::Coding.hex_to_bytes(hex1)
    bytes2 = Cryptopals::Coding.hex_to_bytes(hex2)

    result_bytes = Cryptopals::Operations.xor(bytes1, bytes2)
    Cryptopals::Coding.bytes_to_hex(result_bytes).should eq(hex3)
  end
end
