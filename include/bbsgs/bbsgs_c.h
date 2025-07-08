#ifndef BBSGS_C_H
#define BBSGS_C_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the underlying pairing library. Must be called once.
void bbs04_init_pairing();

// Setup generates the main cryptographic keys.
// The caller is responsible for freeing all output buffers using free_byte_buffer.
void bbs04_setup_c(
    unsigned char** gpk_out, size_t* gpk_len_out,
    unsigned char** osk_out, size_t* osk_len_out,
    unsigned char** isk_out, size_t* isk_len_out
);

// Keygen generates a secret key for a new user.
void bbs04_user_keygen_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* isk_in, size_t isk_len_in,
    unsigned char** usk_out, size_t* usk_len_out
);

// Sign creates a group signature for a message.
void bbs04_sign_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* usk_in, size_t usk_len_in,
    const unsigned char* msg_in, size_t msg_len_in,
    unsigned char** sig_out, size_t* sig_len_out
);

// Verify checks if a signature is valid. Returns 1 for valid, 0 for invalid.
int bbs04_verify_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    const unsigned char* msg_in, size_t msg_len_in
);

// Open reveals the original signer's credential from a signature.
void bbs04_open_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* osk_in, size_t osk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    unsigned char** credential_A_out, size_t* credential_A_len_out
);

// Frees memory allocated by the C++ library.
void free_byte_buffer(unsigned char* buf);

#ifdef __cplusplus
}
#endif

#endif // BBSGS_C_H