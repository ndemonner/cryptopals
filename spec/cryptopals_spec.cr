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

  it "Set 1, Challenge 3: Single-byte XOR cipher" do
    cipher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipher_bytes = Cryptopals::Coding.hex_to_bytes(cipher_text)
    xor_byte = Cryptopals::Operations.find_single_byte_xor_cipher(cipher_bytes)
    plain_bytes = Cryptopals::Operations.bytes_xor_byte(cipher_bytes, xor_byte)
    plain_text = String.new(plain_bytes)
    plain_text.should eq("Cooking MC's like a pound of bacon")
  end

  it "Set 1, Challenge 4: Detect single-character XOR" do
    lines = File.read_lines(File.dirname(__FILE__) + "/data/s1_c4.txt")
    lines.each do |line|
      cipher_bytes = Cryptopals::Coding.hex_to_bytes(line)
      if Cryptopals::Operations.likely_single_byte_xor_encrypted?(cipher_bytes)
        cipher = Cryptopals::Operations.find_single_byte_xor_cipher(cipher_bytes)
        puts String.new(Cryptopals::Operations.bytes_xor_byte(cipher_bytes, cipher))
      end
    end
  end
end
