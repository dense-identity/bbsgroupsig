#ifndef SHIM_ECGROUP_HPP
#define SHim_ECGROUP_HPP

#include <mcl/bn256.hpp>
#include <vector>
#include <string>

namespace ecgroup {

    // Define a byte vector type for clarity
    using Bytes = std::vector<uint8_t>;

    constexpr size_t FR_SERIALIZED_SIZE = 32;
    constexpr size_t G1_SERIALIZED_SIZE = 32;
    constexpr size_t G2_SERIALIZED_SIZE = 64;

    class G1Point;
    class G2Point;
    class PairingResult;
    class Scalar;

    void init_pairing();

    class Scalar {
    public:
        Scalar();

        void set_random();
        Scalar inverse() const;
        std::string to_string() const;
        Bytes to_bytes() const;

        static Scalar hash_to_scalar(const std::string& message);
        static Scalar from_string(const std::string& s);
        static Scalar from_bytes(const Bytes& b);

        bool operator==(const Scalar& other) const;

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

        bool operator==(const PairingResult& other) const;

        explicit PairingResult(const mcl::bn::Fp12& v);

    private:
        mcl::bn::Fp12 value;
    };

    PairingResult pairing(const G1Point& p, const G2Point& q);

} // namespace ecgroup

#endif // SHIM_ECGROUP_HPP
