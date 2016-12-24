require "base64"

module Cryptopals
  class Operations
    NOT_EQUAL_LENGTH = "Operands are not equal length"

    def self.xor(first : Bytes, second : Bytes) : Bytes
      raise NOT_EQUAL_LENGTH unless first.size == second.size
      Bytes.new(first.size) do |i|
        first[i] ^ second[i]
      end
    end
  end
end