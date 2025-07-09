#ifndef SHIM_ECGROUP_HPP
#define SHIM_ECGROUP_HPP

#include <mcl/bn.hpp>
#include <vector>
#include <string>

namespace ecgroup {

    // Define a byte vector type for clarity
    using Bytes = std::vector<uint8_t>;

    // These sizes are consistent with MCL's default serialization for BN256
    constexpr size_t FR_SERIALIZED_SIZE = 32;
    constexpr size_t G1_SERIALIZED_SIZE = 32; // MCL serializes G1 in compressed form by default
    constexpr size_t G2_SERIALIZED_SIZE = 64; // MCL serializes G2 in compressed form by default
    constexpr size_t GT_SERIALIZED_SIZE = 384;

    class G1Point;
    class G2Point;
    class PairingResult;
    class Scalar;

    void init_pairing();

    class Scalar {
    public:
        Scalar();
        Scalar(const mcl::bn::Fr& v): value(v) {};

        void set_random();
        static Scalar get_random();
        Scalar inverse() const;
        Scalar negate() const;
        static Scalar add(const Scalar& a, const Scalar& b);
        static Scalar mul(const Scalar& a, const Scalar& b);
        static Scalar neg(const Scalar& s);

        std::string to_string() const;
        Bytes to_bytes() const;

        static Scalar hash_to_scalar(const std::string& message);
        static Scalar hash_to_scalar(const Bytes& data);
        static Scalar from_string(const std::string& s);
        static Scalar from_bytes(const Bytes& b);

        bool operator==(const Scalar& other) const;
        Scalar operator+(const Scalar& other) const;
        Scalar operator*(const Scalar& other) const;

        const mcl::bn::Fr& get_underlying() const;
        mcl::bn::Fr& get_underlying();

    private:
        mcl::bn::Fr value;
    };

    class G1Point {
    public:
        G1Point();

        std::string to_string() const;
        Bytes to_bytes() const;

        static G1Point get_random();
        static G1Point hash_and_map_to(const std::string& message);
        static G1Point mul(const G1Point& p, const Scalar& s);
        static G1Point from_string(const std::string& s);
        static G1Point from_bytes(const Bytes& b);
        G1Point add(const G1Point& other) const;
        G1Point negate() const;

        bool operator==(const G1Point& other) const;

        const mcl::bn::G1& get_underlying() const;

    private:
        mcl::bn::G1 value;
    };

    class G2Point {
    public:
        G2Point();

        std::string to_string() const;
        Bytes to_bytes() const;

        static G2Point get_random();
        static G2Point get_generator();
        static G2Point mul(const G2Point& p, const Scalar& s);
        static G2Point from_string(const std::string& s);
        static G2Point from_bytes(const Bytes& b);
        G2Point add(const G2Point& other) const;

        bool operator==(const G2Point& other) const;

        const mcl::bn::G2& get_underlying() const;

    private:
        mcl::bn::G2 value;
    };

    class PairingResult {
    public:
        PairingResult();
        explicit PairingResult(const mcl::bn::Fp12& v);

        bool operator==(const PairingResult& other) const;
        const mcl::bn::Fp12& get_underlying() const;

        Bytes to_bytes() const;
        
        // Exponentiation and multiplication
        PairingResult pow(const Scalar& s) const;
        static PairingResult mul(const PairingResult& a, const PairingResult& b);
        PairingResult operator*(const PairingResult& other) const;

        // Division
        static PairingResult div(const PairingResult& a, const PairingResult& b); // New
        PairingResult operator/(const PairingResult& other) const; // New

    private:
        mcl::bn::Fp12 value;
    };

    PairingResult pairing(const G1Point& p, const G2Point& q);

} // namespace ecgroup

#endif // SHIM_ECGROUP_HPP