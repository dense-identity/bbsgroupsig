#ifndef BBSGS_HELPERS_HPP
#define BBSGS_HELPERS_HPP

#include "ecgroup.hpp"

namespace bbsgs {
namespace utils {

    std::string bytes_to_hex(const ecgroup::Bytes& bytes);
    ecgroup::Bytes hex_to_bytes(const std::string& hex);

} // namespace utils
} // namespace bbsgs

#endif // BBSGS_HELPERS_HPP