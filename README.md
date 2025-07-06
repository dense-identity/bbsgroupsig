# C++ Implementation of BBS04 Group Signatures

This repository provides a C++ implementation of the group signature scheme proposed by [Boneh, Boyen, and Shacham in 2004 (BBS04)](https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf). The scheme allows members of a group to sign messages on behalf of the group without revealing their individual identities. However, in the case of a dispute, a designated group manager can revoke a user's anonymity and trace the signature back to the original signer.

This implementation is built upon the high-performance [mcl](https://github.com/herumi/mcl) pairing-based cryptography library and is designed to be both secure and efficient.

## Features

* **Full BBS04 Protocol**: Implements all core algorithms of the scheme:
    * `setup`: Generates the group public key and keys for the issuer/opener.
    * `keygen`: Creates a secret key for a new group member.
    * `sign`: Generates a group signature on a message.
    * `verify`: Verifies if a group signature is valid for a given message.
    * `open`: Allows the group manager to identify the signer of a valid signature.
* **Performance Optimized**: Utilizes pairing product equations to significantly speed up the most computationally expensive operations:
    * **Verification**: Reduces the number of pairing computations from 5 to 2 as described in [https://github.com/hl-tang/JPBC-BBS04/blob/main/README.pdf](https://github.com/hl-tang/JPBC-BBS04/blob/main/README.pdf).
    * **Signing**: Reduces the number of pairing computations from 3 to 2 as described in [/docs/optimizations.md](/docs/optimizations.md).
* **Constant-Time Security**: Leverages the `mcl` library.
* **Clean Abstraction**: Provides a clear and easy-to-use API, separating the low-level elliptic curve math (`ecgroup`) from the high-level protocol logic (`bbsgs`).
* **Testing and Benchmarking**: Includes a comprehensive test suite using Catch2 and a benchmark utility to measure the performance of all critical operations.

## Dependencies
You should have the following dependencies installed to build and run this library:

* A C++17 compliant compiler (e.g., GCC, Clang)
* [CMake](https://cmake.org/) (version 3.10 or later)
* [MCL Library](https://github.com/herumi/mcl): A library for pairing-based cryptography.

We also use [Catch2](https://github.com/catchorg/Catch2) for unit testing but it is automatically installed via CMake's `FetchContent` module.


## How to Build and Run

1.  **Clone the repository and its submodules** (MCL and Catch2):
    ```bash
    git clone --recursive https://github.com/dense-identity/bbsgroupsig
    cd bbsgroupsig
    ```

2.  **Build the project using CMake**:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

3.  **Run the tests**:
    ```bash
    ./build/tests/run_bbsgs_tests
    ```
    All tests should pass.

4.  **Run the benchmarks**:
    ```bash
    ./build/benchmarks/run_bbsgs_benchmarks
    ```
    This will output the average execution time in milliseconds for each cryptographic operation.

## API Usage Example

The following example demonstrates the end-to-end flow of the BBS04 scheme. You can also take a look at the `benchmarks/bench.cpp` and `tests/test_bbsgs.cpp` files for more detailed usage.

```cpp
#include <iostream>
#include "bbsgs/bbsgs.hpp"

int main() {
    // Initialize the underlying pairing library
    ecgroup::init_pairing();

    // 1. SETUP: The group manager generates the system parameters
    bbsgs::GroupPublicKey gpk;
    bbsgs::OpenerSecretKey osk;
    bbsgs::IssuerSecretKey isk;
    bbsgs::bbs04_setup(gpk, osk, isk);
    std::cout << "✅ System setup complete." << std::endl;

    // 2. JOIN: A new user requests and receives a secret key
    bbsgs::UserSecretKey usk = bbsgs::bbs04_user_keygen(isk, gpk);
    std::cout << "✅ User key generated." << std::endl;

    // 3. SIGN: The user signs a message
    ecgroup::Bytes message = {'h', 'e', 'l', 'l', 'o'};
    bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
    std::cout << "✅ Message signed." << std::endl;

    // 4. VERIFY: A third party verifies the signature
    bool is_valid = bbsgs::bbs04_verify(gpk, message, sigma);
    if (is_valid) {
        std::cout << "✅ Signature is VALID." << std::endl;
    } else {
        std::cout << "❌ Signature is INVALID." << std::endl;
    }

    // 5. OPEN: In case of a dispute, the manager traces the signature
    ecgroup::G1Point opened_A = bbsgs::bbs04_open(gpk, osk, sigma);

    // Check if the opened credential matches the user's original credential
    if (opened_A == usk.A) {
        std::cout << "✅ Signature successfully opened and traced to the user." << std::endl;
    } else {
        std::cout << "❌ Failed to open the signature." << std::endl;
    }

    return 0;
}
