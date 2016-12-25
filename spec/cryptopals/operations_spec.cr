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
end

