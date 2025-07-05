#include <chrono>

#include "bbsgs/bbsgs.hpp"

int numIters = 1000;

// create start_timer function
std::chrono::high_resolution_clock::time_point start_timer() {
    return std::chrono::high_resolution_clock::now();
}

// stop_timer uses numIters to calculate the elapsed time average in ms
void stop_timer(std::string testname, std::chrono::high_resolution_clock::time_point& start) {
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    std::cout << testname << " time: " << elapsed.count() / numIters << " ms (average)" << std::endl;
}

void bench_pairing() {
    ecgroup::G1Point p = ecgroup::G1Point::get_random();
    ecgroup::G2Point q = ecgroup::G2Point::get_random();
    
    auto start = start_timer();
    for (int i = 0; i < numIters; ++i) {
        ecgroup::pairing(p, q);
    }
    stop_timer("Pairing", start);
}

void bench_bbs04_setup() {
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;

    auto start = start_timer();
    for (int i = 0; i < numIters; ++i) {
        bbs04_setup(gpk, osk, isk);
    }
    stop_timer("Setup", start);
}

void bench_bbs04_user_keygen() {
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    bbsgs::UserSecretKey usk;

    bbs04_setup(gpk, osk, isk);

    auto start = start_timer();
    for (int i = 0; i < numIters; ++i) {
        usk = bbs04_user_keygen(isk, gpk);
    }
    stop_timer("User Key Generation", start);
}

void bench_bbs04_sign() {
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    std::string msg = "hello world"; 

    bbs04_setup(gpk, osk, isk);
    bbsgs::UserSecretKey usk = bbs04_user_keygen(isk, gpk);

    auto start = start_timer();
    bbsgs::GroupSignature sigma;
    for (int i = 0; i < numIters; ++i) {
        sigma = bbs04_sign(gpk, usk, ecgroup::Bytes(msg.begin(), msg.end()));
    }
    stop_timer("Signging", start);

    std::cout << "Group Signature: " << bbsgs::utils::bytes_to_hex(sigma.to_bytes()) << std::endl;
}

int main(int argc, char* argv[])
{
    ecgroup::init_pairing();

    // bench_pairing();
    // bench_bbs04_setup();
    // bench_bbs04_user_keygen();

    bench_bbs04_sign();

    return 0;
}