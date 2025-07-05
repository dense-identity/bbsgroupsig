#include "keys.hpp"
#include "helpers.hpp"

namespace bbs04 {

    // --- GroupPublicKey Implementation ---
    std::string GroupPublicKey::to_string() const {
        // Use the helper from the new namespace
        return utils::bytes_to_hex(this->to_bytes());
    }

    GroupPublicKey GroupPublicKey::from_string(const std::string& s) {
        // Use the helper from the new namespace
        ecgroup::Bytes bytes = utils::hex_to_bytes(s);
        return GroupPublicKey::from_bytes(bytes);
    }

    ecgroup::Bytes GroupPublicKey::to_bytes() const {
        ecgroup::Bytes out;
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
            // Ensure bounds checking for safety, though the sizes are fixed here
            if (offset + len > b.size()) {
                throw std::out_of_range("Attempted to read beyond end of bytes for GroupPublicKey deserialization.");
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


    // --- IssuerSecretKey Implementation ---
    std::string IssuerSecretKey::to_string() const {
        // Use the helper from the new namespace
        return utils::bytes_to_hex(this->to_bytes());
    }

    IssuerSecretKey IssuerSecretKey::from_string(const std::string& s) {
        // Use the helper from the new namespace
        ecgroup::Bytes bytes = utils::hex_to_bytes(s);
        return IssuerSecretKey::from_bytes(bytes);
    }

    ecgroup::Bytes IssuerSecretKey::to_bytes() const {
        ecgroup::Bytes out;
        auto append = [&](const ecgroup::Bytes& b) {
            out.insert(out.end(), b.begin(), b.end());
        };
        append(xi1.to_bytes());
        append(xi2.to_bytes());
        return out;
    }

    IssuerSecretKey IssuerSecretKey::from_bytes(const ecgroup::Bytes& b) {
        IssuerSecretKey isk;
        size_t offset = 0;
        
        auto slice = [&](size_t len) {
            // Ensure bounds checking
            if (offset + len > b.size()) {
                throw std::out_of_range("Attempted to read beyond end of bytes for IssuerSecretKey deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };

        isk.xi1 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));
        isk.xi2 = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));

        return isk;
    }


    // --- UserSecretKey Implementation ---
    std::string UserSecretKey::to_string() const {
        // Use the helper from the new namespace
        return utils::bytes_to_hex(this->to_bytes());
    }

    UserSecretKey UserSecretKey::from_string(const std::string& s) {
        // Use the helper from the new namespace
        ecgroup::Bytes bytes = utils::hex_to_bytes(s);
        return UserSecretKey::from_bytes(bytes);
    }

    ecgroup::Bytes UserSecretKey::to_bytes() const {
        ecgroup::Bytes out;
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
            // Ensure bounds checking
            if (offset + len > b.size()) {
                throw std::out_of_range("Attempted to read beyond end of bytes for UserSecretKey deserialization.");
            }
            ecgroup::Bytes sub(b.begin() + offset, b.begin() + offset + len);
            offset += len;
            return sub;
        };

        usk.A = ecgroup::G1Point::from_bytes(slice(ecgroup::G1_SERIALIZED_SIZE));
        usk.x = ecgroup::Scalar::from_bytes(slice(ecgroup::FR_SERIALIZED_SIZE));

        return usk;
    }

} // namespace bbs04