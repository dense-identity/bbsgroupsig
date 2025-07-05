#ifndef BBSGS_KEYS_HPP
#define BBSGS_KEYS_HPP

#include "ecgroup.hpp"
#include "helpers.hpp"
#include <string>
#include <vector>

namespace bbsgs {

    struct GroupPublicKey {
        ecgroup::G1Point g1;
        ecgroup::G2Point g2;
        ecgroup::G1Point h;
        ecgroup::G1Point u;
        ecgroup::G1Point v;
        ecgroup::G2Point w;

        ecgroup::Bytes to_bytes() const;
        static GroupPublicKey from_bytes(const ecgroup::Bytes& b);
    };

    struct OpenerSecretKey {
        ecgroup::Scalar xi1;
        ecgroup::Scalar xi2;

        ecgroup::Bytes to_bytes() const;
        static OpenerSecretKey from_bytes(const ecgroup::Bytes& b);
    };

    struct IssuerSecretKey {
        ecgroup::Scalar gamma;

        ecgroup::Bytes to_bytes() const;
        static IssuerSecretKey from_bytes(const ecgroup::Bytes& b);
    };

    struct UserSecretKey {
        ecgroup::G1Point A;
        ecgroup::Scalar x;

        ecgroup::Bytes to_bytes() const;
        static UserSecretKey from_bytes(const ecgroup::Bytes& b);
    };

    struct GroupSignature {
        ecgroup::G1Point T1;
        ecgroup::G1Point T2;
        ecgroup::G1Point T3;
        ecgroup::Scalar c;
        ecgroup::Scalar s_alpha;
        ecgroup::Scalar s_beta;
        ecgroup::Scalar s_x;
        ecgroup::Scalar s_delta_1;
        ecgroup::Scalar s_delta_2;

        ecgroup::Bytes to_bytes() const;
        static GroupSignature from_bytes(const ecgroup::Bytes& b);
    };

} // namespace bbsgs

#endif // BBSGS_KEYS_HPP
