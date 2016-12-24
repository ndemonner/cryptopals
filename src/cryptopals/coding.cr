require "base64"

module Cryptopals
  class Coding
    HEX_PATTERN = /\A[0-9a-f]*\z/i
    MUST_BE_HEX = "`hex` must be a valid hexstring (size multiple of 2 and /\A[0-9a-f]*\z/)"
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    def self.hex_to_base64(hex : String) : String
      bytes = hex_to_bytes(hex)
      bytes_to_base64(bytes)
    end

    def self.hex_to_bytes(hex : String) : Bytes
      raise MUST_BE_HEX unless (hex.size % 2 == 0) && hex.match(HEX_PATTERN)
      Bytes.new(hex.bytesize / 2) do |i|
        hex[i * 2, 2].to_u8(16)
      end
    end

    def self.bytes_to_base64(bytes : Bytes) : String
      Base64.strict_encode(bytes)
    end

    def self.base64_to_bytes(encoded : String) : Bytes
      Base64.decode(encoded)
    end

    def self.bytes_to_hex(bytes : Bytes) : String
      bytes.hexstring
    end
  end
end