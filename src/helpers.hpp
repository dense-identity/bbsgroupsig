#include <iomanip>

namespace {

    // Converts a vector of bytes to a hex string.
    std::string bytes_to_hex(const ecgroup::Bytes& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto& byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    // Converts a hex string to a vector of bytes.
    ecgroup::Bytes hex_to_bytes(const std::string& hex) {
        ecgroup::Bytes bytes;
        if (hex.length() % 2 != 0) {
            // Or throw an exception, depending on desired error handling
            return bytes; 
        }
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

} // anonymous namespace