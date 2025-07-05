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
    // std::cout << "GroupPublicKey gpk: " << bbsgs::utils::bytes_to_hex(gpk.to_bytes()) << std::endl;
}

int main(int argc, char* argv[])
{
    ecgroup::init_pairing();

    bench_pairing();
    bench_bbs04_setup();

    return 0;
}