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
      test_scores = (0_u8..255_u8).reduce({} of UInt8 => UInt64) do |test_score, test_byte|
        test_score[test_byte] = cipher_bytes.reduce(0_u64) do |byte_score, cipher_byte|
          xored_byte = cipher_byte ^ test_byte
          if xored_byte.chr.ascii_letter? || xored_byte.chr.ascii_whitespace?
            byte_score + 1
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

    def self.hamming_distance(bytes1 : Bytes, bytes2 : Bytes) : UInt64
      distance = 0_u64
      i = 0
      while i < bytes1.size
        val = bytes1[i] ^ bytes2[i]
        while val != 0
          distance += 1;
          val &= val - 1;
        end
        i += 1
      end
      distance
    end

    def self.break_repeating_xor_encryption(cipher_bytes : Bytes, output_key? : Boolean = false) : Bytes
      edit_distances = (4..40).reduce({} of Int32 => Float64) do |acc, key_size_guess|
        chunks = [] of Bytes
        total_distance = 0_u64
        n_chunks = (cipher_bytes.size / key_size_guess) - 1
        i = 0

        while i < n_chunks
          first_chunk = cipher_bytes[key_size_guess * i, key_size_guess]
          second_chunk = cipher_bytes[key_size_guess * (i + 1), key_size_guess]
          total_distance += hamming_distance(first_chunk, second_chunk)
          i += 2
        end

        average_distance = total_distance.fdiv((n_chunks / 2))
        acc[key_size_guess] = average_distance.fdiv(key_size_guess)
        acc
      end

      # take the key size with the smallest normalize edit distance
      key_size = edit_distances
        .keys
        .sort_by { |s| edit_distances[s] }
        .first

      blocks = cipher_bytes.in_groups_of(key_size, 0_u8)
      key_byte_array = [] of UInt8
      blocks.transpose.each_with_index do |block, i|
        key_byte_array << find_single_byte_xor_cipher(Bytes.new(block.to_unsafe, block.size))
      end
      key_bytes = Bytes.new(key_byte_array.to_unsafe, key_byte_array.size)
      
      if output_key?
        puts "\n\nThe key (S #{key_size}, ED #{edit_distances[key_size]}) is: #{String.new(key_bytes)}\n\n"
      end

      Cryptopals::Operations.repeating_xor(cipher_bytes, key_bytes)
    end
  end
end