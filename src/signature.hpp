#ifndef BBSGS_SIGNATURE_HPP
#define BBSGS_SIGNATURE_HPP

#include "keys.hpp"

namespace bbsgs {

    using namespace ecgroup;

    GroupSignature bbs04_sign(GroupPublicKey const &gpk, UserSecretKey const &usk, ecgroup::Bytes const &message);
    bool verify(GroupPublicKey const &gpk, ecgroup::Bytes const &message, GroupSignature const &sigma);
    ecgroup::G1Point open(GroupPublicKey const &gpk, OpenerSecretKey const &osk, ecgroup::Bytes const &message, GroupSignature const &sigma);

    Scalar hash_all_to_scalar(
        const Bytes& message,
        const G1Point& T1, const G1Point& T2, const G1Point& T3,
        const G1Point& R1, const G1Point& R2, const PairingResult& R3,
        const G1Point& R4, const G1Point& R5);

} // namespace bbsgs

#endif // BBSGS_SIGNATURE_HPP
