require "../spec_helper"

describe Cryptopals::Operations do  
  it "#xor" do
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Cryptopals::Operations.xor(Bytes[0b0], Bytes[0b1]).should eq(Bytes[0b1])
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b0]).should eq(Bytes[0b1])
  end

  it "#find_single_byte_xor_cipher" do
    plain_text = "this is a secret message"
    plain_bytes = plain_text.to_slice
    cipher = "x".bytes.first
    cipher_bytes = Cryptopals::Operations.bytes_xor_byte(plain_bytes, cipher)
    
    found_cipher = Cryptopals::Operations.find_single_byte_xor_cipher(cipher_bytes)
    found_cipher.should eq(cipher)

    decrypted_bytes = Cryptopals::Operations.bytes_xor_byte(cipher_bytes, cipher)
    String.new(decrypted_bytes).should eq(plain_text)
  end

  it "#repeating_xor" do
    plain_text = "secret"
    plain_bytes = plain_text.to_slice
    cipher = "key".to_slice
    cipher_bytes = Cryptopals::Operations.repeating_xor(plain_bytes, cipher)
    cipher_bytes.should eq(Bytes[24, 0, 26, 25, 0, 13])
  end

  it "#hamming_distance" do
    str1 = "this is a test"
    str2 = "wokka wokka!!!"
    Cryptopals::Operations.hamming_distance(str1.to_slice, str2.to_slice).should eq(37_u64)
  end
end
