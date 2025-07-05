#include "ecgroup.hpp"

namespace ecgroup {

    void init_pairing() {
        mcl::bn::initPairing();
    }

    // --- Scalar Implementation ---
    Scalar::Scalar() {}
    
    void Scalar::set_random() { value.setRand(); }

    Scalar Scalar::get_random() {
        Scalar s;
        s.set_random();
        return s;
    }

    Scalar Scalar::inverse() const {
        Scalar inv;
        mcl::bn::Fr::inv(inv.value, this->value);
        return inv;
    }
    std::string Scalar::to_string() const { return value.getStr(16); }
    Bytes Scalar::to_bytes() const {
        Bytes b(FR_SERIALIZED_SIZE);
        value.serialize(b.data(), b.size());
        return b;
    }
    Scalar Scalar::hash_to_scalar(const std::string& message) {
        Scalar s;
        s.value.setHashOf(message);
        return s;
    }
    Scalar Scalar::from_string(const std::string& s) {
        Scalar scalar;
        scalar.value.setStr(s, 16);
        return scalar;
    }
    Scalar Scalar::from_bytes(const Bytes& b) {
        Scalar scalar;
        scalar.value.deserialize(b.data(), b.size());
        return scalar;
    }
    bool Scalar::operator==(const Scalar& other) const { return value == other.value; }
    const mcl::bn::Fr& Scalar::get_underlying() const { return value; }
    mcl::bn::Fr& Scalar::get_underlying() { return value; }

    // --- G1Point Implementation ---
    G1Point::G1Point() {}
    std::string G1Point::to_string() const { return value.getStr(16); }
    Bytes G1Point::to_bytes() const {
        Bytes b(G1_SERIALIZED_SIZE);
        value.serialize(b.data(), b.size());
        return b;
    }
    G1Point G1Point::get_random() {
        Scalar s;
        s.set_random();
        G1Point g1_generator = G1Point::hash_and_map_to("ecgroup_g1_generator");
        return G1Point::mul(g1_generator, s);
    }
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
    G1Point G1Point::from_string(const std::string& s) {
        G1Point p;
        p.value.setStr(s, 16);
        return p;
    }
    G1Point G1Point::from_bytes(const Bytes& b) {
        G1Point p;
        p.value.deserialize(b.data(), b.size());
        return p;
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
    std::string G2Point::to_string() const { return value.getStr(16); }
    Bytes G2Point::to_bytes() const {
        Bytes b(G2_SERIALIZED_SIZE);
        value.serialize(b.data(), b.size());
        return b;
    }
    G2Point G2Point::get_random() {
        Scalar s;
        s.set_random();
        G2Point g2_generator = G2Point::get_generator();
        return G2Point::mul(g2_generator, s);
    }
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
    G2Point G2Point::from_string(const std::string& s) {
        G2Point p;
        p.value.setStr(s, 16);
        return p;
    }
    G2Point G2Point::from_bytes(const Bytes& b) {
        G2Point p;
        p.value.deserialize(b.data(), b.size());
        return p;
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
