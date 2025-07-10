#ifndef BBSGS_C_H
#define BBSGS_C_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BBSGS_OK  0
#define BBSGS_ERR (-1)

// Initialize the underlying pairing library. Must be called once.
void bbs04_init_pairing();

// Setup generates the main cryptographic keys.
// The caller is responsible for freeing all output buffers using free_byte_buffer.
int bbs04_setup_c(
    unsigned char** gpk_out, size_t* gpk_len_out,
    unsigned char** osk_out, size_t* osk_len_out,
    unsigned char** isk_out, size_t* isk_len_out
);

// Keygen generates a secret key for a new user.
int bbs04_user_keygen_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* isk_in, size_t isk_len_in,
    unsigned char** usk_out, size_t* usk_len_out
);

// Sign creates a group signature for a message.
int bbs04_sign_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* usk_in, size_t usk_len_in,
    const unsigned char* msg_in, size_t msg_len_in,
    unsigned char** sig_out, size_t* sig_len_out
);

// Check if generated user secret key is valid for group parameters.
int bbs04_verify_usk_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* usk_in, size_t usk_len_in
);

// Verify checks if a signature is valid. Returns 1 for valid, 0 for invalid.
int bbs04_verify_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    const unsigned char* msg_in, size_t msg_len_in
);

// Open reveals the original signer's credential from a signature.
int bbs04_open_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* osk_in, size_t osk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    unsigned char** credential_A_out, size_t* credential_A_len_out
);

// ------------------------------------------------------------------------
// EC scalar & G1 helpers
// ------------------------------------------------------------------------

// Generate a random scalar.  
// Outputs a big-endian byte-array scalar in [1, order-1].
int ec_scalar_random(
    unsigned char** scalar_out, size_t* scalar_len_out
);

// Compute multiplicative inverse of a scalar.
// scalar_in is a BE byte-array; scalar_out is its inverse mod group order.
int ec_scalar_inverse(
    const unsigned char* scalar_in, size_t scalar_len_in,
    unsigned char** scalar_inv_out, size_t* scalar_inv_len_out
);

// Hash arbitrary message to a G1 point (using your chosen hash-to-curve).
int ec_g1_hash_to_point(
    const unsigned char* msg, size_t msg_len,
    unsigned char** point_out, size_t* point_len_out
);

// Multiply a G1 point by a scalar.
// point_in is a byte-array representation of a G1 point.
int ec_g1_mul(
    const unsigned char* point_in, size_t point_len_in,
    const unsigned char* scalar_in, size_t scalar_len_in,
    unsigned char** point_out, size_t* point_len_out
);

// Frees any buffer previously allocated by the library.
void free_byte_buffer(unsigned char* buf);

#ifdef __cplusplus
}
#endif

#endif // BBSGS_C_H
