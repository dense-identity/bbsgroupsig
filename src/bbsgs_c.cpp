#include "bbsgs/bbsgs_c.h"
#include "bbsgs/bbsgs.hpp"
#include <vector>
#include <cstring>
#include <string>

// Helper to copy a C++ Bytes vector to a newly allocated C buffer
void copy_to_c_buf(const ecgroup::Bytes& vec, unsigned char** buf_out, size_t* len_out) {
    *len_out = vec.size();
    *buf_out = new unsigned char[*len_out];
    memcpy(*buf_out, vec.data(), *len_out);
}

void bbs04_init_pairing() {
    ecgroup::init_pairing();
}

int bbs04_setup_c(
    unsigned char** gpk_out, size_t* gpk_len_out,
    unsigned char** osk_out, size_t* osk_len_out,
    unsigned char** isk_out, size_t* isk_len_out)
{
    try {
        bbsgs::GroupPublicKey gpk;
        bbsgs::OpenerSecretKey osk;
        bbsgs::IssuerSecretKey isk;
        bbsgs::bbs04_setup(gpk, osk, isk);
    
        copy_to_c_buf(gpk.to_bytes(), gpk_out, gpk_len_out);
        copy_to_c_buf(osk.to_bytes(), osk_out, osk_len_out);
        copy_to_c_buf(isk.to_bytes(), isk_out, isk_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int bbs04_user_keygen_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* isk_in, size_t isk_len_in,
    unsigned char** usk_out, size_t* usk_len_out)
{
    try {
        ecgroup::Bytes gpk_bytes(gpk_in, gpk_in + gpk_len_in);
        ecgroup::Bytes isk_bytes(isk_in, isk_in + isk_len_in);
    
        bbsgs::GroupPublicKey  gpk = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
        bbsgs::IssuerSecretKey isk = bbsgs::IssuerSecretKey::from_bytes(isk_bytes);
    
        bbsgs::UserSecretKey usk = bbsgs::bbs04_user_keygen(isk, gpk);
        copy_to_c_buf(usk.to_bytes(), usk_out, usk_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int bbs04_sign_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* usk_in, size_t usk_len_in,
    const unsigned char* msg_in, size_t msg_len_in,
    unsigned char** sig_out, size_t* sig_len_out)
{
    try {
        ecgroup::Bytes gpk_bytes(gpk_in, gpk_in + gpk_len_in);
        ecgroup::Bytes usk_bytes(usk_in, usk_in + usk_len_in);
        ecgroup::Bytes msg_bytes(msg_in, msg_in + msg_len_in);
    
        bbsgs::GroupPublicKey  gpk = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
        bbsgs::UserSecretKey   usk = bbsgs::UserSecretKey::from_bytes(usk_bytes);
    
        bbsgs::GroupSignature sigma = bbsgs::bbs04_sign(gpk, usk, msg_bytes);
        copy_to_c_buf(sigma.to_bytes(), sig_out, sig_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int bbs04_verify_usk_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* usk_in, size_t usk_len_in)
{
    ecgroup::Bytes gpk_bytes(gpk_in, gpk_in + gpk_len_in);
    ecgroup::Bytes usk_bytes(usk_in, usk_in + usk_len_in);

    bbsgs::GroupPublicKey gpk = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
    bbsgs::UserSecretKey  usk = bbsgs::UserSecretKey::from_bytes(usk_bytes);

    return bbsgs::bbs04_verify_usk(gpk, usk) ? 1 : 0;
}

int bbs04_verify_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    const unsigned char* msg_in, size_t msg_len_in)
{
    ecgroup::Bytes gpk_bytes(gpk_in, gpk_in + gpk_len_in);
    ecgroup::Bytes sig_bytes(sig_in, sig_in + sig_len_in);
    ecgroup::Bytes msg_bytes(msg_in, msg_in + msg_len_in);

    bbsgs::GroupPublicKey  gpk   = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
    bbsgs::GroupSignature  sigma = bbsgs::GroupSignature::from_bytes(sig_bytes);

    return bbsgs::bbs04_verify(gpk, msg_bytes, sigma) ? 1 : 0;
}

int bbs04_open_c(
    const unsigned char* gpk_in, size_t gpk_len_in,
    const unsigned char* osk_in, size_t osk_len_in,
    const unsigned char* sig_in, size_t sig_len_in,
    unsigned char** credential_A_out, size_t* credential_A_len_out)
{
    try {
        ecgroup::Bytes gpk_bytes(gpk_in,  gpk_in  + gpk_len_in);
        ecgroup::Bytes osk_bytes(osk_in,  osk_in  + osk_len_in);
        ecgroup::Bytes sig_bytes(sig_in,  sig_in  + sig_len_in);
    
        bbsgs::GroupPublicKey  gpk   = bbsgs::GroupPublicKey::from_bytes(gpk_bytes);
        bbsgs::OpenerSecretKey osk   = bbsgs::OpenerSecretKey::from_bytes(osk_bytes);
        bbsgs::GroupSignature  sigma = bbsgs::GroupSignature::from_bytes(sig_bytes);
    
        ecgroup::G1Point opened_A = bbsgs::bbs04_open(gpk, osk, sigma);
        copy_to_c_buf(opened_A.to_bytes(), credential_A_out, credential_A_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

// ------------------------------------------------------------------------
// EC scalar & G1 helpers
// ------------------------------------------------------------------------

int ec_scalar_random(
    unsigned char** scalar_out, size_t* scalar_len_out)
{
    try {
        ecgroup::Bytes s = ecgroup::Scalar::get_random().to_bytes();
        copy_to_c_buf(s, scalar_out, scalar_len_out);
        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int ec_scalar_inverse(
    const unsigned char* scalar_in, size_t scalar_len_in,
    unsigned char** scalar_inv_out, size_t* scalar_inv_len_out)
{
    try {
        ecgroup::Scalar s = ecgroup::Scalar::from_bytes(ecgroup::Bytes(scalar_in, scalar_in + scalar_len_in));
        ecgroup::Bytes inv = s.inverse().to_bytes();
        copy_to_c_buf(inv, scalar_inv_out, scalar_inv_len_out);
        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int ec_g1_hash_to_point(
    const unsigned char* msg, size_t msg_len,
    unsigned char** point_out, size_t* point_len_out)
{
    try {
        std::string m(msg, msg + msg_len);
        ecgroup::G1Point P = ecgroup::G1Point::hash_and_map_to(m);
        copy_to_c_buf(P.to_bytes(), point_out, point_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

int ec_g1_mul(
    const unsigned char* point_in, size_t point_len_in,
    const unsigned char* scalar_in, size_t scalar_len_in,
    unsigned char** point_out, size_t* point_len_out)
{
    try {
        ecgroup::Scalar scalar = ecgroup::Scalar::from_bytes(ecgroup::Bytes(scalar_in, scalar_in + scalar_len_in));
        ecgroup::G1Point point = ecgroup::G1Point::from_bytes(ecgroup::Bytes(point_in, point_in + point_len_in));
        ecgroup::G1Point res = ecgroup::G1Point::mul(point, scalar);
        copy_to_c_buf(res.to_bytes(), point_out, point_len_out);

        return BBSGS_OK;
    } catch(...) {
        return BBSGS_ERR;
    }
}

void free_byte_buffer(unsigned char* buf) {
    delete[] buf;
}
