#include "keys.hpp"
#include <stdexcept> // Required for std::out_of_range

namespace bbsgs {

    ecgroup::Bytes GroupPublicKey::to_bytes() const {
        ecgroup::Bytes out;
        out.reserve(4 * ecgroup::G1_SERIALIZED_SIZE + 2 * ecgroup::G2_SERIALIZED_SIZE);
        auto append = [&](const ecgroup::Bytes& b) {
            out.insert(out.end(), b.begin(), b.end());
        };
        append(g1.to_bytes());
        append(h.to_bytes());
        append(u.to_bytes());
        append(v.to_bytes());
        append(g2.to_bytes());
        append(w.to_bytes());
        return out;
    }

    GroupPublicKey GroupPublicKey::from_bytes(const ecgroup::Bytes& b) {
        GroupPublicKey gpk;
        size_t offset = 0;
        
        auto slice = [&](size_t len) {
            if (offset + len > b.size()) {
                throw std::out_of_range("Not enough bytes for GroupPublicKey deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };

        gpk.g1 = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        gpk.h = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        gpk.u = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        gpk.v = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        gpk.g2 = ecgroup::G2Point::from_bytes(slice(ecgroup::G2_SERIALIZED_SIZE));
        gpk.w = ecgroup::G2Point::from_bytes(slice(ecgroup::G2_SERIALIZED_SIZE));

        return gpk;
    }


    ecgroup::Bytes OpenerSecretKey::to_bytes() const {
        ecgroup::Bytes out;
        out.reserve(2 * ecgroup::FR_SERIALIZED_SIZE);
        auto append = [&](const ecgroup::Bytes& b) {
            out.insert(out.end(), b.begin(), b.end());
        };
        append(xi1.to_bytes());
        append(xi2.to_bytes());
        return out;
    }

    OpenerSecretKey OpenerSecretKey::from_bytes(const ecgroup::Bytes& b) {
        OpenerSecretKey isk;
        size_t offset = 0;
        
        auto slice = [&](size_t len) {
            if (offset + len > b.size()) {
                throw std::out_of_range("Not enough bytes for OpenerSecretKey deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };

        isk.xi1 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        isk.xi2 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));

        return isk;
    }

    ecgroup::Bytes IssuerSecretKey::to_bytes() const {
        return gamma.to_bytes();
    }

    IssuerSecretKey IssuerSecretKey::from_bytes(const ecgroup::Bytes& b) {
        IssuerSecretKey ok;
        ok.gamma = ecgroup::Scalar::from_bytes(b);
        return ok;
    }

    ecgroup::Bytes UserSecretKey::to_bytes() const {
        ecgroup::Bytes out;
        out.reserve(ecgroup::G1_SERIALIZED_SIZE + ecgroup::FR_SERIALIZED_SIZE);
        auto append = [&](const ecgroup::Bytes& b) {
            out.insert(out.end(), b.begin(), b.end());
        };
        append(A.to_bytes());
        append(x.to_bytes());
        return out;
    }

    UserSecretKey UserSecretKey::from_bytes(const ecgroup::Bytes& b) {
        UserSecretKey usk;
        size_t offset = 0;
        
        auto slice = [&](size_t len) {
            if (offset + len > b.size()) {
                throw std::out_of_range("Not enough bytes for UserSecretKey deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };

        usk.A = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        usk.x = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));

        return usk;
    }

    // --- New Implementation for GroupSignature ---

    ecgroup::Bytes GroupSignature::to_bytes() const {
        ecgroup::Bytes out;
        // 3 G1 points and 6 Scalars, all 32 bytes each
        out.reserve(9 * ecgroup::G1_SERIALIZED_SIZE); 
        
        auto append = [&](const ecgroup::Bytes& b) {
            out.insert(out.end(), b.begin(), b.end());
        };

        // Append all components in a fixed, deterministic order
        append(T1.to_bytes());
        append(T2.to_bytes());
        append(T3.to_bytes());
        append(c.to_bytes());
        append(s_alpha.to_bytes());
        append(s_beta.to_bytes());
        append(s_x.to_bytes());
        append(s_delta_1.to_bytes());
        append(s_delta_2.to_bytes());
        
        return out;
    }

    GroupSignature GroupSignature::from_bytes(const ecgroup::Bytes& b) {
        GroupSignature sig;
        size_t offset = 0;

        auto slice = [&](size_t len) {
            if (offset + len > b.size()) {
                throw std::out_of_range("Not enough bytes for GroupSignature deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };
        
        // Extract all components in the same order they were appended
        sig.T1 = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        sig.T2 = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        sig.T3 = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        sig.c = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        sig.s_alpha = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        sig.s_beta = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        sig.s_x = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        sig.s_delta_1 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        sig.s_delta_2 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));

        return sig;
    }

} // namespace bbsgs