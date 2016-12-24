require "../spec_helper"

Mod = Cryptopals::Operations

describe Mod do
  it "#xor" do
    Mod.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Mod.xor(Bytes[0b0], Bytes[0b1]).should eq(Bytes[0b1])
    Mod.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Mod.xor(Bytes[0b1], Bytes[0b0]).should eq(Bytes[0b1])
  end

  it "#find_single_byte_xor_cipher" do
    plain_text = "this is a secret message"
    plain_bytes = plain_text.to_slice
    cipher = "x".bytes.first
    cipher_bytes = Mod.xor(plain_bytes, Bytes.new(plain_bytes.size, cipher))
    
    found_cipher = Mod.find_single_byte_xor_cipher(cipher_bytes)
    found_cipher.should eq(cipher)

    decrypted_bytes = Mod.xor(cipher_bytes, Bytes.new(cipher_bytes.size, cipher))
    String.new(decrypted_bytes).should eq(plain_text)
  end
end
