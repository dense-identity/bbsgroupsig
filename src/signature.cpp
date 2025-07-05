#include "signature.hpp"

namespace bbsgs {

    GroupSignature bbs04_sign(GroupPublicKey const &gpk, UserSecretKey const &usk, ecgroup::Bytes const &message) {
        GroupSignature sigma;

        // Sample alpha and beta
        ecgroup::Scalar alpha = ecgroup::Scalar::get_random();
        ecgroup::Scalar beta = ecgroup::Scalar::get_random();

        // Compute T1, T2, T3
        sigma.T1 = ecgroup::G1Point::mul(gpk.u, alpha);
        sigma.T2 = ecgroup::G1Point::mul(gpk.v, beta);
        sigma.T3 = usk.A.add(ecgroup::G1Point::mul(gpk.h, ecgroup::Scalar::add(alpha, beta)));

        // Sample r_values
        ecgroup::Scalar r_alpha = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_beta = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_x = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_delta_1 = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_delta_2 = ecgroup::Scalar::get_random();


        ecgroup::G1Point R1 = ecgroup::G1Point::mul(gpk.u, r_alpha);
        ecgroup::G1Point R2 = ecgroup::G1Point::mul(gpk.v, r_beta);
        ecgroup::PairingResult R3 = ecgroup::pairing(sigma.T3, gpk.g2).pow(r_x) 
                                    * ecgroup::pairing(gpk.h, gpk.w).pow(ecgroup::Scalar::add(r_alpha.negate(), r_beta.negate()))
                                    * ecgroup::pairing(gpk.h, gpk.g2).pow(ecgroup::Scalar::add(r_delta_1.negate(), r_delta_2.negate()));
                                    
        ecgroup::G1Point R4 = ecgroup::G1Point::mul(sigma.T1, r_x).add(ecgroup::G1Point::mul(gpk.u, r_delta_1.negate()));
        ecgroup::G1Point R5 = ecgroup::G1Point::mul(sigma.T2, r_x).add(ecgroup::G1Point::mul(gpk.v, r_delta_2.negate()));

        sigma.c = hash_all_to_scalar(message, sigma.T1, sigma.T2, sigma.T3, R1, R2, R3, R4, R5);
        sigma.s_alpha = r_alpha + (sigma.c * alpha);
        sigma.s_beta = r_beta + (sigma.c * beta);
        sigma.s_x = r_x + (sigma.c * usk.x);
        sigma.s_delta_1 = r_delta_1 + (sigma.c * (usk.x * alpha));
        sigma.s_delta_2 = r_delta_2 + (sigma.c * (usk.x * beta));

        return sigma;
    };

    // bool verify(GroupPublicKey const &gpk, ecgroup::Bytes const &message, GroupSignature const &sigma) {};

    // ecgroup::G1Point open(GroupPublicKey const &gpk, OpenerSecretKey const &osk, ecgroup::Bytes const &message, GroupSignature const &sigma) {};

    Scalar hash_all_to_scalar(
        const Bytes& message,
        const G1Point& T1, const G1Point& T2, const G1Point& T3,
        const G1Point& R1, const G1Point& R2, const PairingResult& R3,
        const G1Point& R4, const G1Point& R5) 
    {
        const size_t total_size = message.size() +
                                  (7 * G1_SERIALIZED_SIZE) + // T1,T2,T3,R1,R2,R4,R5 are G1
                                  GT_SERIALIZED_SIZE;        // R3 is Gt

        Bytes to_hash;
        to_hash.reserve(total_size);

        auto append = [&](const Bytes& b) {
            to_hash.insert(to_hash.end(), b.begin(), b.end());
        };
        
        append(message);
        append(T1.to_bytes());
        append(T2.to_bytes());
        append(T3.to_bytes());
        append(R1.to_bytes());
        append(R2.to_bytes());
        append(R3.to_bytes());
        append(R4.to_bytes());
        append(R5.to_bytes());
        
        return Scalar::hash_to_scalar(to_hash);
    }

} // namespace bbsgs