require "base64"

module Cryptopals
  class Operations
    NOT_EQUAL_LENGTH = "Operands are not equal length"
    MOST_FREQUENT_ENGLISH_LETTER_BYTES = "etaoinshrdlu".bytes

    def self.xor(first : Bytes, second : Bytes) : Bytes
      raise NOT_EQUAL_LENGTH unless first.size == second.size
      Bytes.new(first.size) do |i|
        first[i] ^ second[i]
      end
    end

    def self.find_single_byte_xor_cipher(cipher_bytes : Bytes) : UInt8
      # first build a frequency map of bytes
      frequency_map = cipher_bytes.reduce({} of UInt8 => UInt64) do |acc, byte|
        acc[byte] ||= 0_u64
        acc[byte] += 1_u64
        acc
      end

      # next, score each possible byte by how likely it is that it xors to the right letter
      test_scores = (0_u8..255_u8).reduce({} of UInt8 => Float64) do |test_score, test_byte|
        test_score[test_byte] = frequency_map.keys.reduce(0.0) do |key_score, key_byte|
          if MOST_FREQUENT_ENGLISH_LETTER_BYTES.includes?(key_byte ^ test_byte)
            occurrence_ratio = frequency_map[key_byte].fdiv(cipher_bytes.size)
            key_score + occurrence_ratio
          else
            key_score
          end
        end
        test_score
      end
      
      test_scores.keys.reduce do |acc, key|
        test_scores[key] > test_scores[acc] ? key : acc
      end
    end

    def self.likely_single_byte_xor_encrypted?(bytes : Bytes) : Bool
      cipher_byte = find_single_byte_xor_cipher(bytes);
      plain_bytes = bytes_xor_byte(bytes, cipher_byte)
      plain_bytes.all? { |byte| byte <= 127 }
    end

    def self.bytes_xor_byte(bytes : Bytes, key : UInt8) : Bytes
      xor(bytes, Bytes.new(bytes.size, key))
    end
  end
end