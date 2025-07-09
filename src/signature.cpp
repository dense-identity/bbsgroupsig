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
        sigma.T3 = usk.A.add(ecgroup::G1Point::mul(gpk.h, alpha + beta));

        // Sample r_values (nonces for the ZKP)
        ecgroup::Scalar r_alpha = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_beta = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_x = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_delta_1 = ecgroup::Scalar::get_random();
        ecgroup::Scalar r_delta_2 = ecgroup::Scalar::get_random();

        // Compute R values (commitments for the ZKP)
        ecgroup::G1Point R1 = ecgroup::G1Point::mul(gpk.u, r_alpha);
        ecgroup::G1Point R2 = ecgroup::G1Point::mul(gpk.v, r_beta);

        /**
         * Applying the optimization logic found in this repo /docs/optimizations.md to compute R3 quickly.
         */
        
        ecgroup::G1Point t3_pow_rx = ecgroup::G1Point::mul(sigma.T3, r_x);
        ecgroup::Scalar r_d_sum = r_delta_1 + r_delta_2;
        ecgroup::G1Point h_term_g2 = ecgroup::G1Point::mul(gpk.h, r_d_sum).negate();

        ecgroup::G1Point pairing1_arg = t3_pow_rx.add(h_term_g2);

        ecgroup::Scalar r_ab_sum_neg = (r_alpha + r_beta).negate();
        ecgroup::G1Point pairing2_arg = ecgroup::G1Point::mul(gpk.h, r_ab_sum_neg);

        ecgroup::PairingResult e_g2 = ecgroup::pairing(pairing1_arg, gpk.g2);
        ecgroup::PairingResult e_w = ecgroup::pairing(pairing2_arg, gpk.w);
        ecgroup::PairingResult R3 = e_g2 * e_w;

        ecgroup::G1Point R4 = ecgroup::G1Point::mul(sigma.T1, r_x).add(ecgroup::G1Point::mul(gpk.u, r_delta_1.negate()));
        ecgroup::G1Point R5 = ecgroup::G1Point::mul(sigma.T2, r_x).add(ecgroup::G1Point::mul(gpk.v, r_delta_2.negate()));

        // Create challenge and responses
        sigma.c = hash_all_to_scalar(message, sigma.T1, sigma.T2, sigma.T3, R1, R2, R3, R4, R5);
        sigma.s_alpha = r_alpha + sigma.c * alpha;
        sigma.s_beta = r_beta + sigma.c * beta;
        sigma.s_x = r_x + sigma.c * usk.x;
        sigma.s_delta_1 = r_delta_1 + sigma.c * (usk.x * alpha);
        sigma.s_delta_2 = r_delta_2 + sigma.c * (usk.x * beta);

        return sigma;
    };

    bool bbs04_verify(GroupPublicKey const &gpk, ecgroup::Bytes const &message, GroupSignature const &sigma) {
        // Recompute the R commitments using the s-values from the signature
        // R'_1 = u^s_alpha * T1^-c
        ecgroup::G1Point R1_prime = ecgroup::G1Point::mul(gpk.u, sigma.s_alpha)
                                    .add(ecgroup::G1Point::mul(sigma.T1, sigma.c.negate()));

        // R'_2 = v^s_beta * T2^-c
        ecgroup::G1Point R2_prime = ecgroup::G1Point::mul(gpk.v, sigma.s_beta)
                                    .add(ecgroup::G1Point::mul(sigma.T2, sigma.c.negate()));

        // R'_4 = T1^s_x * u^-s_delta_1
        ecgroup::G1Point R4_prime = ecgroup::G1Point::mul(sigma.T1, sigma.s_x)
                                    .add(ecgroup::G1Point::mul(gpk.u, sigma.s_delta_1.negate()));
        
        // R'_5 = T2^s_x * v^-s_delta_2
        ecgroup::G1Point R5_prime = ecgroup::G1Point::mul(sigma.T2, sigma.s_x)
                                    .add(ecgroup::G1Point::mul(gpk.v, sigma.s_delta_2.negate()));
        
        /**
         * Applying the optimization logic found in https://github.com/hl-tang/JPBC-BBS04/blob/main/README.pdf
         * to compute R3 quickly.
         */
        // R'_3 = e(T3,g2)^s_x * e(h,w)^-(s_alpha+s_beta) * e(h,g2)^-(s_delta1+s_delta2) * [e(T3,w)/e(g1,g2)]^c
        ecgroup::G1Point t3_pow_sx = ecgroup::G1Point::mul(sigma.T3, sigma.s_x);
        ecgroup::Scalar s_d_sum = sigma.s_delta_1 + sigma.s_delta_2;
        ecgroup::G1Point h_term = ecgroup::G1Point::mul(gpk.h, s_d_sum).negate();
        ecgroup::G1Point g1_term = ecgroup::G1Point::mul(gpk.g1, sigma.c).negate();

        ecgroup::G1Point pairing1_arg1 = t3_pow_sx.add(h_term).add(g1_term);

        // arg2 = T3^c * h^-(s_alpha + s_beta)
        ecgroup::G1Point t3_pow_c = ecgroup::G1Point::mul(sigma.T3, sigma.c);
        ecgroup::Scalar s_ab_sum = sigma.s_alpha + sigma.s_beta;
        ecgroup::G1Point h_term2 = ecgroup::G1Point::mul(gpk.h, s_ab_sum).negate();

        ecgroup::G1Point pairing2_arg1 = t3_pow_c.add(h_term2);

        ecgroup::PairingResult e1 = ecgroup::pairing(pairing1_arg1, gpk.g2);
        ecgroup::PairingResult e2 = ecgroup::pairing(pairing2_arg1, gpk.w);
        ecgroup::PairingResult R3_prime = e1 * e2;
        
        // Hash the recomputed R values to get the challenge
        ecgroup::Scalar c_prime = hash_all_to_scalar(
            message, sigma.T1, sigma.T2, sigma.T3,
            R1_prime, R2_prime, R3_prime, R4_prime, R5_prime
        );

        // The signature is valid if the recomputed challenge matches the original one
        return c_prime == sigma.c;
    };

    ecgroup::G1Point bbs04_open(const GroupPublicKey& gpk, const OpenerSecretKey& osk, const GroupSignature& sigma) {
        // Calculate T1^xi1
        ecgroup::G1Point t1_pow_xi1 = ecgroup::G1Point::mul(sigma.T1, osk.xi1);

        // Calculate T2^xi2
        ecgroup::G1Point t2_pow_xi2 = ecgroup::G1Point::mul(sigma.T2, osk.xi2);
        
        // Calculate h^(a+b) = (T1^xi1) * (T2^xi2)
        ecgroup::G1Point h_pow_ab = t1_pow_xi1.add(t2_pow_xi2);
        
        // Recover A = T3 * (h^(a+b))^-1, which is T3 + (-h^(a+b))
        return sigma.T3.add(h_pow_ab.negate());
    }

    bool bbs04_verify_usk(const GroupPublicKey& gpk, const UserSecretKey& usk) {
        ecgroup::G2Point w_g2x = gpk.w.add(ecgroup::G2Point::mul(gpk.g2, usk.x));
        ecgroup::PairingResult e1 = ecgroup::pairing(usk.A, w_g2x);
        ecgroup::PairingResult e2 = ecgroup::pairing(gpk.g1, gpk.g2);

        return e1 == e2;
    }

    Scalar hash_all_to_scalar(
        const ecgroup::Bytes& message,
        const ecgroup::G1Point& T1, const ecgroup::G1Point& T2, const ecgroup::G1Point& T3,
        const ecgroup::G1Point& R1, const ecgroup::G1Point& R2, const ecgroup::PairingResult& R3,
        const ecgroup::G1Point& R4, const ecgroup::G1Point& R5) 
    {
        const size_t total_size = message.size() +
                                  (7 * ecgroup::G1_SERIALIZED_SIZE) +
                                  ecgroup::GT_SERIALIZED_SIZE;

        ecgroup::Bytes to_hash;
        to_hash.reserve(total_size);

        auto append = [&](const ecgroup::Bytes& b) {
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
        
        return ecgroup::Scalar::hash_to_scalar(to_hash);
    }

} // namespace bbsgs