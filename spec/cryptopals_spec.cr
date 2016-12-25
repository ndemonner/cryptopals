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
    plain_texts = lines.map do |line|
      cipher_bytes = Cryptopals::Coding.hex_to_bytes(line)
      cipher = Cryptopals::Operations.find_single_byte_xor_cipher(cipher_bytes)
      plain_bytes = Cryptopals::Operations.bytes_xor_byte(cipher_bytes, cipher)
      String.new(plain_bytes).chomp
    end
    plain_texts.includes?("Now that the party is jumping").should be_true
  end

  it "Set 1, Challenge 5: Implement repeating-key XOR" do
    expected_cipher_text = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    plain_bytes = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_slice
    cipher_bytes = Cryptopals::Operations.repeating_xor(plain_bytes, "ICE".to_slice)
    cipher_text = Cryptopals::Coding.bytes_to_hex(cipher_bytes)
    cipher_text.should eq(expected_cipher_text)
  end
end
