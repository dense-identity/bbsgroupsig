# BBS04 Group Signature Go Bindings

This directory contains the Go bindings for the BBS04 C++ library (with C wrapper) supporting group signatures. It uses cgo and pkg-config to link against the installed C library.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building & Installing the C Library](#building--installing-the-c-library)
3. [Setting Up Go Bindings](#setting-up-go-bindings)
4. [Usage Example](#usage-example)
5. [Running Tests and Benchmarks](#running-tests-and-benchmarks)
6. [Troubleshooting](#troubleshooting)
7. [License](#license)

---

## Prerequisites

Before installing the Go bindings, ensure you have the following tools installed and available in your `PATH`:

* **Go** (any version with module support, e.g., 1.16+)
* **CMake** (version ≥ 3.15)
* **pkg-config**
* A C/C++ compiler toolchain (e.g., `gcc`/`g++` or `clang`)
* **MCL** library and headers (pairing-friendly elliptic curve library). See [MCL repository](https://github.com/herumi/mcl)

## Building & Installing the C Library

1. **Clone the repository** (if you haven’t already):

   ```bash
   git clone https://github.com/dense-identity/bbsgroupsig.git
   cd bbsgroupsig
   ```

2. **Build and install** the library and headers:
    Run the script located in `bindings/install.sh` script to build and install the C library:
    ```bash
    ./bindings/install.sh
    ```

   By default, this installs to `/usr/`. To change the install location, pass `-DCMAKE_INSTALL_PREFIX=/your/path` to the `cmake` command in `install.sh`.

4. **Verify** the pkg-config file is available:

   ```bash
   pkg-config --modversion bbsgs
   ```

   You should see the version number (e.g., `1.0.0`). If not, ensure `PKG_CONFIG_PATH` includes the directory where `bbsgs.pc` was installed (e.g., `/usr/lib/pkgconfig`).

## Running Tests and Benchmarks

From the `bindings/go` directory:

* **Unit tests**:

  ```bash
  go test ./...
  ```

* **Benchmarks**:

  ```bash
  go test -bench=. -benchmem
  ```

## Using Go Bindings

Add the binding as a dependency** in your project:

```bash
go get github.com/dense-identity/bbsgroupsig/bindings/go@latest
```

## Usage Example

```go
package main

import (
    "fmt"
    "github.com/dense-identity/bbsgroupsig/bindings/go"
)

func main() {
    // Initialize pairing (must be called once)
    bbsgs.InitPairing()

    // 1. Generate keys
    gpk, osk, isk, err := bbsgs.Setup()
    if err != nil {
        panic(err)
    }

    // 2. Create a user secret key
    usk, err := bbsgs.UserKeygen(gpk, isk)
    if err != nil {
        panic(err)
    }

    // 3. Sign a message
    msg := []byte("Hello, BBS04!")
    sig, err := bbsgs.Sign(gpk, usk, msg)
    if err != nil {
        panic(err)
    }

    // 4. Verify
    valid := bbsgs.Verify(gpk, sig, msg)
    fmt.Printf("Signature valid? %v\n", valid)

    // 5. Open the signature
    credA, err := bbsgs.Open(gpk, osk, sig)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Revealed credential A length: %d bytes\n", len(credA))
}
```

## Troubleshooting

* **`pkg-config` not found**: ensure `pkg-config` is installed (`sudo apt install pkg-config` or `brew install pkg-config`).
* **Cannot find libraries**: confirm that `bbsgs.pc` is in your `PKG_CONFIG_PATH` and libraries are under the matching `libdir`.
* **cgo errors**: run `go env CGO_ENABLED` and ensure it prints `1`.

