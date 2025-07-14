# C++ Implementation of BBS04 Group Signatures

This repository provides a C++ implementation of the group signature scheme proposed by Boneh, Boyen, and Shacham in their paper [Short Group Signatures](https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf). The scheme allows members of a group to sign messages on behalf of the group without revealing their individual identities. However, in the case of a dispute, a designated group manager can revoke a user's anonymity and trace the signature back to the original signer.

This implementation is built upon the high-performance [mcl](https://github.com/herumi/mcl) pairing-based cryptography library and is designed to be both secure and efficient.

## Table of Contents

- [Features](#features)
- [Language Bindings](#language-bindings)
- [Dependencies](#dependencies)
- [How to Build and Run](#how-to-build-and-run)
- [API Usage Example](#api-usage-example)


## Features

* **Full BBS04 Protocol**: Implements all core algorithms of the scheme:
    * `setup`: Generates the group public key and keys for the issuer/opener.
    * `keygen`: Creates a secret key for a new group member.
    * `sign`: Generates a group signature on a message.
    * `verify`: Verifies if a group signature is valid for a given message.
    * `open`: Allows the group manager to identify the signer of a valid signature.
* **t-of-n Threshold Variants**: In progress, this implementation will support [distributed variants](https://www.orbs.com/assets/docs/white-papers/Crypto_Group_signatures-2.pdf) of the BBS04 scheme, allowing for more flexible group management and security models.
* **Performance Optimized**: Utilizes pairing product equations to significantly speed up the most computationally expensive operations:
    * **Verification**: Reduces the number of pairing computations from 5 to 2 as described in [https://github.com/hl-tang/JPBC-BBS04/blob/main/README.pdf](https://github.com/hl-tang/JPBC-BBS04/blob/main/README.pdf).
    * **Signing**: Reduces the number of pairing computations from 3 to 2 as described in [/docs/optimizations.md](/docs/optimizations.md).
* **Constant-Time Security**: Leverages the `mcl` library.
* **Clean Abstraction**: Provides a clear and easy-to-use API, separating the low-level elliptic curve math (`ecgroup`) from the high-level protocol logic (`bbsgs`).
* **Testing and Benchmarking**: Includes a comprehensive test suite using Catch2 and a benchmark utility to measure the performance of all critical operations.


## Language Bindings

This C++ library is the core implementation, but it can be used in other programming languages through foreign function interface (FFI) wrappers. All official language bindings are located in the `bindings/` directory.

### Go
A Go package is available that provides a complete, idiomatic wrapper around the C++ library. For detailed instructions on how to set up your environment and use the package in your Go projects, please refer to the Go binding's dedicated README:

➡️ **[bindings/go/README.md](./bindings/go/README.md)**


## Dependencies
You should have the following dependencies installed to build and run this library:

* A C++17 compliant compiler (e.g., GCC, Clang)
* [CMake](https://cmake.org/) (version 3.10 or later)
* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/): Required for building language bindings.
* If building for android:
    * JDK 11
    * Android NDK
    * GMP

The following dependencies are fetched and built automatically by CMake and do not require manual installation:
* **MCL Library**
* **Catch2** (for testing)


## How to Build and Run

1.  **Clone the repository and its submodules** (MCL and Catch2):
    ```bash
    git clone https://github.com/dense-identity/bbsgroupsig
    cd bbsgroupsig
    ```

2.  **Build the project using CMake**:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```
    This will build the C++ static libraries and any language bindings configured in the build system.

3.  **Run the tests**:
    ```bash
    ./build/tests/run_bbsgs_tests
    ```
    All tests should pass.

    ```bash
    ./build/tests/run_bbsgs_tests 
    Randomness seeded to: 3585119377
    ===============================================================================
    All tests passed (34 assertions in 2 test cases)
    ```

4.  **Run the benchmarks**:
    ```bash
    ./build/benchmarks/run_bbsgs_benchmarks
    ```
    This will output the average execution time in milliseconds for each cryptographic operation. The results below are run on a VM with 32 vCPUs and 62GB RAM.
    ```bash
    ./build/benchmarks/run_bbsgs_benchmarks 
    --- Low-Level Cryptographic Primitives (Avg over 10000 iters) ---
    Scalar Multiplication       : 0.000063 ms
    G1 Scalar Multiplication    : 0.060911 ms
    G2 Scalar Multiplication    : 0.096481 ms
    Pairing Exponentiation      : 0.245335 ms
    Pairing                     : 0.463038 ms

    --- High-Level Protocol Operations (Avg over 100 iters) ---
    Full Setup                  : 1.205559 ms
    User Key Generation         : 0.066865 ms
    Sign                        : 1.732059 ms
    Verify                      : 1.792356 ms
    Open                        : 0.127576 ms
    ```

## API Usage Example

The following example demonstrates the end-to-end flow of the BBS04 scheme. You can also take a look at the `benchmarks/bench.cpp` and `tests/test_bbsgs.cpp` files for more detailed usage.

### Include the necessary headers:
```cpp
#include "bbsgs/bbsgs.hpp"
```

### Initialize MCL pairing functionality.
```cpp
ecgroup::init_pairing();
```
This step is necessary to set up the elliptic curve and pairing parameters used by the BBS04 scheme. It should be done only once at the start of your program.

### SETUP: The group manager generates the system parameters
```cpp
bbsgs::GroupPublicKey gpk;
bbsgs::OpenerSecretKey osk;
bbsgs::IssuerSecretKey isk;
bbsgs::bbs04_setup(gpk, osk, isk);
```
### JOIN: A new user requests and receives a secret key
```cpp
bbsgs::UserSecretKey usk = bbsgs::bbs04_user_keygen(isk, gpk);
```

### SIGN: The user signs a message
```cpp
ecgroup::Bytes message = {'h', 'e', 'l', 'l', 'o'};
bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, message);
```

### VERIFY: A third party verifies the signature
```cpp
bool is_valid = bbsgs::bbs04_verify(gpk, message, sigma);
if (is_valid) {
    std::cout << "✅ Signature is VALID." << std::endl;
} else {
    std::cout << "❌ Signature is INVALID." << std::endl;
}
```

### OPEN: In case of a dispute, the manager traces the signature
```cpp
ecgroup::G1Point opened_A = bbsgs::bbs04_open(gpk, osk, sigma);

// Check if the opened credential matches the user's original credential
if (opened_A == usk.A) {
    std::cout << "✅ Signature successfully opened and traced to the user." << std::endl;
} else {
    std::cout << "❌ Failed to open the signature." << std::endl;
}
```