#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>

#include "bbsgs/bbsgs.hpp"

/**
 * @brief A simple class to run benchmarks and print formatted results.
 */
class BenchmarkRunner {
public:
    int num_iters;

    explicit BenchmarkRunner(int iterations) : num_iters(iterations) {}

    void run(const std::string& name, const std::function<void()>& func) {
        // Run once to warm up caches, JIT, etc.
        func(); 

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_iters; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;

        std::cout << std::left << std::setw(28) << name 
                  << ": " << std::fixed << std::setprecision(6) 
                  << elapsed.count() / num_iters << " ms" << std::endl;
    }
};

int main() {
    ecgroup::init_pairing();

    BenchmarkRunner primitive_runner(10000); // More iterations for fast ops
    BenchmarkRunner protocol_runner(100);    // Fewer iterations for slow ops

    // =====================================================================
    // SECTION 1: Low-Level Cryptographic Primitives
    // =====================================================================
    std::cout << "--- Low-Level Cryptographic Primitives (Avg over " << primitive_runner.num_iters << " iters) ---" << std::endl;

    ecgroup::Scalar s1 = ecgroup::Scalar::get_random();
    ecgroup::Scalar s2 = ecgroup::Scalar::get_random();
    primitive_runner.run("Scalar Multiplication", [&]() {
        auto r = s1 * s2;
    });

    ecgroup::G1Point p1 = ecgroup::G1Point::get_random();
    primitive_runner.run("G1 Scalar Multiplication", [&]() {
        auto r = ecgroup::G1Point::mul(p1, s1);
    });

    ecgroup::G2Point p2 = ecgroup::G2Point::get_random();
    primitive_runner.run("G2 Scalar Multiplication", [&]() {
        auto r = ecgroup::G2Point::mul(p2, s1);
    });
    
    ecgroup::PairingResult pr = ecgroup::pairing(p1, p2);
    primitive_runner.run("Pairing Exponentiation", [&]() {
        auto r = pr.pow(s1);
    });

    protocol_runner.run("Pairing", [&]() { // Pairing is slower, use fewer iters
        auto r = ecgroup::pairing(p1, p2);
    });


    // =====================================================================
    // SECTION 2: High-Level Protocol Operations
    // =====================================================================
    std::cout << "\n--- High-Level Protocol Operations (Avg over " << protocol_runner.num_iters << " iters) ---" << std::endl;

    // --- One-time setup for all protocol benchmarks ---
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    bbsgs::bbs04_setup(gpk, osk, isk);
    bbsgs::UserSecretKey usk = bbsgs::bbs04_user_keygen(isk, gpk);
    ecgroup::Bytes message = {'t', 'e', 's', 't'};
    bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
    // --- End of setup ---

    protocol_runner.run("Full Setup", [&]() {
        bbsgs::GroupPublicKey gpk_b;
        bbsgs::OpenerSecretKey osk_b;
        bbsgs::IssuerSecretKey isk_b;
        bbsgs::bbs04_setup(gpk_b, osk_b, isk_b);
    });

    protocol_runner.run("User Key Generation", [&]() {
        auto usk_b = bbsgs::bbs04_user_keygen(isk, gpk);
    });

    protocol_runner.run("Sign", [&]() {
        auto sigma_b = bbsgs::bbs04_sign(gpk, usk, message);
    });
    
    protocol_runner.run("Verify", [&]() {
        bbsgs::bbs04_verify(gpk, message, sigma);
    });
    
    protocol_runner.run("Open", [&]() {
        auto opened_A = bbsgs::bbs04_open(gpk, osk, sigma);
    });

    return 0;
}