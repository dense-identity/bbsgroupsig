#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include <vector>

#include "bbsgs/bbsgs.hpp"

TEST_CASE("BBS04 Group Signature Scheme", "[bbsgs]") {
    // Initialize the pairing library once for all tests.
    ecgroup::init_pairing();

    // 1. Setup phase: Generate system-wide keys.
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    bbsgs::bbs04_setup(gpk, osk, isk);

    // 2. Join phase: A new user gets their secret key.
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

    SECTION("Valid Signature and Verification") {
        // Generate a signature for the message
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);

        // Verify the signature
        bool is_valid = bbsgs::bbs04_verify(gpk, message, sigma);
        REQUIRE(is_valid == true);
    }
    
    SECTION("Signature Opening (Tracing)") {
        // 1. Create a valid signature from the user
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);

        // 2. Use the 'open' function to trace the signature
        ecgroup::G1Point opened_A = bbsgs::bbs04_open(gpk, osk, sigma);

        // 3. Check that the opened credential matches the original user's credential
        REQUIRE(opened_A == usk.A);

        // 4. Negative Test: Ensure a tampered signature does not open correctly
        bbsgs::GroupSignature tampered_sigma = sigma;
        tampered_sigma.T1 = ecgroup::G1Point::get_random(); // Corrupt T1
        ecgroup::G1Point garbage_A = bbsgs::bbs04_open(gpk, osk, tampered_sigma);
        REQUIRE_FALSE(garbage_A == usk.A);
    }

    SECTION("Invalid Signature: Wrong Message") {
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
        ecgroup::Bytes wrong_message = {'f', 'a', 'i', 'l'};

        // Verification should fail for a different message
        REQUIRE_FALSE(bbsgs::bbs04_verify(gpk, wrong_message, sigma));
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