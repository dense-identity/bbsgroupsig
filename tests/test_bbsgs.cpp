#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include <vector>

#include "bbsgs/bbsgs.hpp"

TEST_CASE("BBS04 Group Signature Scheme", "[bbsgs]") {
    // Initialize the pairing library once for all tests.
    ecgroup::init_pairing();

    // 1. Setup phase: Generate system-wide keys using your setup function.
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    bbsgs::bbs04_setup(gpk, osk, isk);

    // 2. Join phase: A new user gets their secret key using your keygen function.
    bbsgs::UserSecretKey usk = bbsgs::bbs04_user_keygen(isk, gpk);
    
    // Define a test message
    ecgroup::Bytes message = {'s', 'a', 'm', 'p', 'l', 'e', ' ', 'm', 's', 'g'};

    SECTION("Generated User Key Validity") {
        // After key generation, it's critical to verify that the user's secret key
        // satisfies the fundamental group membership equation: e(A, w * g2^x) == e(g1, g2)
        ecgroup::G2Point w_g2x = gpk.w.add(ecgroup::G2Point::mul(gpk.g2, usk.x));
        ecgroup::PairingResult e1 = ecgroup::pairing(usk.A, w_g2x);
        ecgroup::PairingResult e2 = ecgroup::pairing(gpk.g1, gpk.g2);

        REQUIRE(e1 == e2);
    }

    SECTION("Key Serialization Round-trip") {
        // Test GroupPublicKey
        ecgroup::Bytes gpk_bytes = gpk.to_bytes();
        bbsgs::GroupPublicKey gpk_from_bytes = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
        REQUIRE(gpk.u == gpk_from_bytes.u); // Check a component to confirm deserialization
        REQUIRE(gpk.w == gpk_from_bytes.w);

        // Test UserSecretKey
        ecgroup::Bytes usk_bytes = usk.to_bytes();
        bbsgs::UserSecretKey usk_from_bytes = bbsgs::UserSecretKey::from_bytes(usk_bytes);
        REQUIRE(usk.A == usk_from_bytes.A);
        REQUIRE(usk.x == usk_from_bytes.x);
    }

    SECTION("Valid Signature") {
        // Generate a signature for the message
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);

        // Verify the signature
        bool is_valid = bbsgs::bbs04_verify(gpk, message, sigma);
        REQUIRE(is_valid == true);

        // Also test signature serialization
        ecgroup::Bytes sigma_bytes = sigma.to_bytes();
        bbsgs::GroupSignature sigma_from_bytes = bbsgs::GroupSignature::from_bytes(sigma_bytes);
        REQUIRE(sigma.T1 == sigma_from_bytes.T1);
        REQUIRE(sigma.c == sigma_from_bytes.c);
    }
    
    SECTION("Invalid Signature: Wrong Message") {
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
        ecgroup::Bytes wrong_message = {'f', 'a', 'i', 'l'};

        // Verification should fail for a different message
        bool is_valid = bbsgs::bbs04_verify(gpk, wrong_message, sigma);
        REQUIRE(is_valid == false);
    }

    SECTION("Invalid Signature: Tampered Signature") {
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
        
        // Tamper with a public part of the signature (T1)
        bbsgs::GroupSignature tampered_sigma_T1 = sigma;
        tampered_sigma_T1.T1 = ecgroup::G1Point::get_random();
        REQUIRE_FALSE(bbsgs::bbs04_verify(gpk, message, tampered_sigma_T1));
        
        // Tamper with the challenge (c)
        bbsgs::GroupSignature tampered_sigma_c = sigma;
        tampered_sigma_c.c = ecgroup::Scalar::get_random();
        REQUIRE_FALSE(bbsgs::bbs04_verify(gpk, message, tampered_sigma_c));

        // Tamper with a response value (s_alpha)
        bbsgs::GroupSignature tampered_sigma_s = sigma;
        tampered_sigma_s.s_alpha = ecgroup::Scalar::get_random();
        REQUIRE_FALSE(bbsgs::bbs04_verify(gpk, message, tampered_sigma_s));
    }
}