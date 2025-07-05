#include <catch2/catch_test_macros.hpp>

#include <iostream>
#include "ecgroup.hpp"

// A single test case with sections for better organization.
TEST_CASE("Elliptic Curve Group Operations", "[ecgroup]") {
    // Initialize the pairing library once for all tests in this case.
    ecgroup::init_pairing();

    SECTION("Scalar operations") {
        ecgroup::Scalar s1, s2;
        s1.set_random();
        s2.set_random();

        // A scalar must be equal to itself.
        REQUIRE(s1 == s1);

        // Two different random scalars should not be equal.
        REQUIRE_FALSE(s1 == s2);

        // Test scalar inversion
        ecgroup::Scalar s_inv = s1.inverse();
        ecgroup::Scalar s_inv_inv = s_inv.inverse();
        REQUIRE(s1 == s_inv_inv); // s == (s^-1)^-1

        // Test hashing to scalar
        ecgroup::Scalar h1 = ecgroup::Scalar::hash_to_scalar("test message");
        ecgroup::Scalar h2 = ecgroup::Scalar::hash_to_scalar("test message");
        ecgroup::Scalar h3 = ecgroup::Scalar::hash_to_scalar("another message");
        REQUIRE(h1 == h2);
        REQUIRE_FALSE(h1 == h3);
    }

    SECTION("G1Point operations") {
        ecgroup::G1Point p1 = ecgroup::G1Point::hash_and_map_to("hello world");
        ecgroup::G1Point p2 = ecgroup::G1Point::hash_and_map_to("another message");
        ecgroup::G1Point p1_copy = ecgroup::G1Point::hash_and_map_to("hello world");

        // Hashing the same message should produce the same point.
        REQUIRE(p1 == p1_copy);
        REQUIRE_FALSE(p1 == p2);

        // Test addition
        ecgroup::G1Point p_sum = p1.add(p2);
        REQUIRE_FALSE(p_sum == p1);
        REQUIRE_FALSE(p_sum == p2);

        // Test scalar multiplication
        ecgroup::Scalar s;
        s.set_random();
        ecgroup::G1Point p_mul = ecgroup::G1Point::mul(p1, s);
        REQUIRE_FALSE(p_mul == p1);

        // Test random point generation
        ecgroup::G1Point r1 = ecgroup::G1Point::get_random();
        ecgroup::G1Point r2 = ecgroup::G1Point::get_random();
        ecgroup::G1Point identity; // Default constructor is identity
        REQUIRE_FALSE(r1 == r2);
        REQUIRE_FALSE(r1 == identity);
    }

    SECTION("G2Point operations") {
        ecgroup::G2Point g = ecgroup::G2Point::get_generator();
        ecgroup::G2Point g_copy = ecgroup::G2Point::get_generator();

        // The generator should be deterministic.
        REQUIRE(g == g_copy);

        ecgroup::Scalar s1, s2;
        s1.set_random();
        s2.set_random();

        ecgroup::G2Point p1 = ecgroup::G2Point::mul(g, s1);
        ecgroup::G2Point p2 = ecgroup::G2Point::mul(g, s2);
        REQUIRE_FALSE(p1 == p2);

        // Test addition
        ecgroup::G2Point p_sum = p1.add(p2);
        REQUIRE_FALSE(p_sum == p1);
        REQUIRE_FALSE(p_sum == p2);

        // Test random point generation
        ecgroup::G2Point r1 = ecgroup::G2Point::get_random();
        ecgroup::G2Point r2 = ecgroup::G2Point::get_random();
        ecgroup::G2Point identity; // Default constructor is identity
        REQUIRE_FALSE(r1 == r2);
        REQUIRE_FALSE(r1 == identity);
    }

    SECTION("Pairing properties") {
        // Test the fundamental bilinear property: e(a*P, Q) == e(P, a*Q)
        ecgroup::Scalar s;
        s.set_random();

        ecgroup::G1Point p = ecgroup::G1Point::hash_and_map_to("test point");
        ecgroup::G2Point q = ecgroup::G2Point::get_generator();

        // Calculate a*P in G1
        ecgroup::G1Point p_mul_s = ecgroup::G1Point::mul(p, s);

        // Calculate a*Q in G2
        ecgroup::G2Point q_mul_s = ecgroup::G2Point::mul(q, s);

        // Calculate e(a*P, Q)
        ecgroup::PairingResult e1 = ecgroup::pairing(p_mul_s, q);

        // Calculate e(P, a*Q)
        ecgroup::PairingResult e2 = ecgroup::pairing(p, q_mul_s);

        // The results must be equal.
        REQUIRE(e1 == e2);

        // Also check that the pairing result is not trivial (not equal to a different pairing).
        ecgroup::PairingResult e_trivial = ecgroup::pairing(p, q);
        REQUIRE_FALSE(e1 == e_trivial);
    }

    SECTION("Serialization") {
        // Test round-trip serialization for Scalar
        ecgroup::Scalar s1;
        s1.set_random();
        std::string s1_str = s1.to_string();
        ecgroup::Bytes s1_bytes = s1.to_bytes();

        ecgroup::Scalar s1_from_str = ecgroup::Scalar::from_string(s1_str);
        ecgroup::Scalar s1_from_bytes = ecgroup::Scalar::from_bytes(s1_bytes);
        REQUIRE(s1 == s1_from_str);
        REQUIRE(s1 == s1_from_bytes);

        // Test round-trip serialization for G1Point
        ecgroup::G1Point p1 = ecgroup::G1Point::get_random();
        std::string p1_str = p1.to_string();
        ecgroup::Bytes p1_bytes = p1.to_bytes();
        ecgroup::G1Point p1_from_str = ecgroup::G1Point::from_string(p1_str);
        ecgroup::G1Point p1_from_bytes = ecgroup::G1Point::from_bytes(p1_bytes);
        REQUIRE(p1 == p1_from_str);
        REQUIRE(p1 == p1_from_bytes);

        // Test round-trip serialization for G2Point
        ecgroup::G2Point p2 = ecgroup::G2Point::get_random();
        std::string p2_str = p2.to_string();
        ecgroup::Bytes p2_bytes = p2.to_bytes();
        ecgroup::G2Point p2_from_str = ecgroup::G2Point::from_string(p2_str);
        ecgroup::G2Point p2_from_bytes = ecgroup::G2Point::from_bytes(p2_bytes);
        REQUIRE(p2 == p2_from_str);
        REQUIRE(p2 == p2_from_bytes);
    }
}
