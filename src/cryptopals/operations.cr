require "base64"

module Cryptopals
  class Operations
    NOT_EQUAL_LENGTH = "Operands are not equal length"

    LETTER_FREQUENCIES = {
      'e'.bytes[0] => 0.12702,
      't'.bytes[0] => 0.9056,
      'a'.bytes[0] => 0.8167,
      'o'.bytes[0] => 0.7507,
      'i'.bytes[0] => 0.6966,
      'n'.bytes[0] => 0.6749,
      's'.bytes[0] => 0.6327,
      'h'.bytes[0] => 0.6094,
      'r'.bytes[0] => 0.5987,
      'd'.bytes[0] => 0.4253,
      'l'.bytes[0] => 0.4025,
      'c'.bytes[0] => 0.2782,    
      'u'.bytes[0] => 0.2758
    }

    def self.xor(first : Bytes, second : Bytes) : Bytes
      raise NOT_EQUAL_LENGTH unless first.size == second.size
      Bytes.new(first.size) do |i|
        first[i] ^ second[i]
      end
    end

    def self.find_single_byte_xor_cipher(cipher_bytes : Bytes) : UInt8
      # score each possible byte by how likely it is that it xors to the right letter
      test_scores = (0_u8..255_u8).reduce({} of UInt8 => Float64) do |test_score, test_byte|
        test_score[test_byte] = cipher_bytes.reduce(0.0) do |byte_score, cipher_byte|
          xored_byte = cipher_byte ^ test_byte
          if LETTER_FREQUENCIES.has_key?(xored_byte)
            # increment this byte's score in relation to its english frequency
            byte_score + LETTER_FREQUENCIES[xored_byte]
          else
            byte_score
          end
        end
        test_score
      end
      
      # take the byte with the best score
      test_scores
        .keys
        .sort_by { |s| test_scores[s] }
        .last
    end

    def self.bytes_xor_byte(bytes : Bytes, key : UInt8) : Bytes
      xor(bytes, Bytes.new(bytes.size, key))
    end

    def self.repeating_xor(plain_bytes : Bytes, key_bytes : Bytes) : Bytes
      Bytes.new(plain_bytes.size) do |i|
        plain_bytes[i] ^ key_bytes[i % key_bytes.size]
      end
    end
  end
end