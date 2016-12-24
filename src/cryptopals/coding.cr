module Cryptopals
  class Coding    
    HEX_PATTERN = /\A[0-9a-f]*\z/i
    BYTE_PATTERN = /[0-9a-f]{2}/i
    MUST_BE_HEX = "`hexstring` must be hex-encoded string"
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    def self.hex_to_base64(hexstring : String)
      encode_bytes_to_base64(hex_to_bytes(hexstring))
    end

    def self.hex_to_bytes(hexstring : String)
      raise MUST_BE_HEX unless hexstring.match(HEX_PATTERN)
      hexstring.scan(BYTE_PATTERN).map { |chunk| chunk[0].to_u8(16) }
    end

    def self.encode_bytes_to_base64(bytes : Array(UInt8))
      # Translated from the Java code on the Wikipedia article
      String.build do |str|
        i = 0
        while i < bytes.size
          b = (bytes[i] & 0xfc) >> 2
          str << BASE64_CHARS[b]
          b = (bytes[i] & 0x03) << 4
          if (i + 1 < bytes.size)
            b |= (bytes[i + 1] & 0xf0) >> 4
            str << BASE64_CHARS[b]
            b = (bytes[i + 1] & 0x0f) << 2
            if (i + 2 < bytes.size)
              b |= (bytes[i + 2] & 0xc0) >> 6
              str << BASE64_CHARS[b]
              b = bytes[i + 2] & 0x3f
              str << BASE64_CHARS[b]
            else
              str << BASE64_CHARS[b]
              str << "="
            end
          else
            str << BASE64_CHARS[b]
            str << "=="
          end
          i += 3
        end
      end
    end

    def self.encode_bytes_to_hex(bytes : Array(UInt8))
      bytes.map(&.to_s(16)).join("")
    end
  end
end