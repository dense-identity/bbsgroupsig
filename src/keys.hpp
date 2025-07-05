#ifndef BBS04_KEYS_HPP
#define BBS04_KEYS_HPP

#include "ecgroup.hpp" // For G1Point, G2Point, Scalar

namespace bbs04 {

    // Group Public Key (gpk)
    struct GroupPublicKey {
        ecgroup::G1Point g1;
        ecgroup::G1Point h;
        ecgroup::G1Point u;
        ecgroup::G1Point v;
        ecgroup::G2Point g2;
        ecgroup::G2Point w;
    };

    // Issuer Secret Key (isk)
    struct IssuerSecretKey {
        ecgroup::Scalar xi1;
        ecgroup::Scalar xi2;
    };

    // User Secret Key (usk)
    struct UserSecretKey {
        ecgroup::G1Point A;
        ecgroup::Scalar x;
    };

} // namespace bbs04

#endif // BBS04_KEYS_HPP
