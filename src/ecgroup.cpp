#include "ecgroup.hpp"

namespace ecgroup {

    void init_pairing() {
        mcl::bn::initPairing();
    }

    // --- Scalar Implementation ---
    Scalar::Scalar() {}
    void Scalar::set_random() { value.setRand(); }
    bool Scalar::operator==(const Scalar& other) const { return value == other.value; }
    const mcl::bn::Fr& Scalar::get_underlying() const { return value; }
    mcl::bn::Fr& Scalar::get_underlying() { return value; }

    // --- G1Point Implementation ---
    G1Point::G1Point() {}

    G1Point G1Point::hash_and_map_to(const std::string& message) {
        G1Point p;
        mcl::bn::hashAndMapToG1(p.value, message.c_str(), message.length());
        return p;
    }

    G1Point G1Point::mul(const G1Point& p, const Scalar& s) {
        G1Point result;
        mcl::bn::G1::mul(result.value, p.value, s.get_underlying());
        return result;
    }

    G1Point G1Point::add(const G1Point& other) const {
        G1Point result;
        mcl::bn::G1::add(result.value, this->value, other.value);
        return result;
    }

    bool G1Point::operator==(const G1Point& other) const { return value == other.value; }
    const mcl::bn::G1& G1Point::get_underlying() const { return value; }

    // --- G2Point Implementation ---
    G2Point::G2Point() {}

    G2Point G2Point::get_generator() {
        G2Point g;
        mcl::bn::mapToG2(g.value, 1);
        return g;
    }

    G2Point G2Point::mul(const G2Point& p, const Scalar& s) {
        G2Point result;
        mcl::bn::G2::mul(result.value, p.value, s.get_underlying());
        return result;
    }

    G2Point G2Point::add(const G2Point& other) const {
        G2Point result;
        mcl::bn::G2::add(result.value, this->value, other.value);
        return result;
    }

    bool G2Point::operator==(const G2Point& other) const { return value == other.value; }
    const mcl::bn::G2& G2Point::get_underlying() const { return value; }

    // --- PairingResult Implementation ---
    PairingResult::PairingResult() {}
    PairingResult::PairingResult(const mcl::bn::Fp12& v) : value(v) {}
    bool PairingResult::operator==(const PairingResult& other) const { return value == other.value; }

    // --- Pairing Function Implementation ---
    PairingResult pairing(const G1Point& p, const G2Point& q) {
        mcl::bn::Fp12 e;
        mcl::bn::pairing(e, p.get_underlying(), q.get_underlying());
        return PairingResult(e);
    }

} // namespace ecgroup
