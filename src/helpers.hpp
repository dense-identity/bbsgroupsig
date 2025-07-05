#ifndef BBS04_HELPERS_HPP
#define BBS04_HELPERS_HPP

#include "ecgroup.hpp" // Required for ecgroup::Bytes
#include <iomanip>
#include <sstream>     // For std::stringstream
#include <stdexcept>   // For std::invalid_argument

namespace bbs04 {
namespace utils { // New namespace for helper functions

    // Converts a vector of bytes to a hex string.
    std::string bytes_to_hex(const ecgroup::Bytes& bytes);

    // Converts a hex string to a vector of bytes.
    // Throws std::invalid_argument if the hex string length is odd.
    ecgroup::Bytes hex_to_bytes(const std::string& hex);

} // namespace utils
} // namespace bbs04

// Implementation details for the helper functions
// Placing implementation in .hpp is common for small helper functions
// or when using them across multiple translation units without a separate .cpp
namespace bbs04 {
namespace utils {

    std::string bytes_to_hex(const ecgroup::Bytes& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto& byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    ecgroup::Bytes hex_to_bytes(const std::string& hex) {
        if (hex.length() % 2 != 0) {
            throw std::invalid_argument("Hex string length must be even.");
        }

        ecgroup::Bytes bytes;
        bytes.reserve(hex.length() / 2); // Pre-allocate memory
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            // strtol is safe here for two hex digits
            uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

} // namespace utils
} // namespace bbs04

#endif // BBS04_HELPERS_HPP