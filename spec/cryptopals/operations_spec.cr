require "../spec_helper"

describe Cryptopals::Operations do
  it "#xor" do
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Cryptopals::Operations.xor(Bytes[0b0], Bytes[0b1]).should eq(Bytes[0b1])
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b1]).should eq(Bytes[0b0])
    Cryptopals::Operations.xor(Bytes[0b1], Bytes[0b0]).should eq(Bytes[0b1])
  end
end
