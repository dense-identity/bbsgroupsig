#ifndef BBS04_KEYS_HPP
#define BBS04_KEYS_HPP

#include "ecgroup.hpp"
#include <string>
#include <vector>

namespace bbs04 {

    struct GroupPublicKey {
        ecgroup::G1Point g1;
        ecgroup::G1Point h;
        ecgroup::G1Point u;
        ecgroup::G1Point v;
        ecgroup::G2Point g2;
        ecgroup::G2Point w;

        std::string to_string() const;
        ecgroup::Bytes to_bytes() const;
        static GroupPublicKey from_string(const std::string& s);
        static GroupPublicKey from_bytes(const ecgroup::Bytes& b);
    };

    struct IssuerSecretKey {
        ecgroup::Scalar xi1;
        ecgroup::Scalar xi2;

        std::string to_string() const;
        ecgroup::Bytes to_bytes() const;
        static IssuerSecretKey from_string(const std::string& s);
        static IssuerSecretKey from_bytes(const ecgroup::Bytes& b);
    };

    struct OpenerKey {
        ecgroup::Scalar gamma;

        std::string to_string() const;
        ecgroup::Bytes to_bytes() const;
        static OpenerKey from_string(const std::string& s);
        static OpenerKey from_bytes(const ecgroup::Bytes& b);
    };

    struct UserSecretKey {
        ecgroup::G1Point A;
        ecgroup::Scalar x;

        std::string to_string() const;
        ecgroup::Bytes to_bytes() const;
        static UserSecretKey from_string(const std::string& s);
        static UserSecretKey from_bytes(const ecgroup::Bytes& b);
    };

} // namespace bbs04

#endif // BBS04_KEYS_HPP
