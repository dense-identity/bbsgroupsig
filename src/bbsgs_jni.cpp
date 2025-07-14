#include <jni.h>
#include <stdexcept>
#include <vector>
#include "bbsgs/bbsgs_c.h"

// Helper: throw a Java RuntimeException with the given message
static void throwJavaException(JNIEnv* env, const char* msg) {
    jclass exClass = env->FindClass("java/lang/RuntimeException");
    if (exClass) env->ThrowNew(exClass, msg);
}

// Helper: copy native buffer → new Java byte[]
static jbyteArray toJavaByteArray(JNIEnv* env,
                                  const unsigned char* buf,
                                  size_t len) {
    jbyteArray arr = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(arr, 0, (jsize)len, reinterpret_cast<const jbyte*>(buf));
    free_byte_buffer((unsigned char*)buf);
    return arr;
}

extern "C" {

// void bbs04_init_pairing()
JNIEXPORT void JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1init_1pairing(JNIEnv* env, jclass) {
    bbs04_init_pairing();
}

// SetupResult bbs04_setup()
JNIEXPORT jobject JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1setup(JNIEnv* env, jclass) {
    unsigned char *gpk = nullptr, *osk = nullptr, *isk = nullptr;
    size_t gpk_len=0, osk_len=0, isk_len=0;

    if (bbs04_setup_c(&gpk,&gpk_len,&osk,&osk_len,&isk,&isk_len) != BBSGS_OK) {
        throwJavaException(env, "bbs04_setup_c failed");
        return nullptr;
    }

    jbyteArray jgpk = toJavaByteArray(env, gpk, gpk_len);
    jbyteArray josk = toJavaByteArray(env, osk, osk_len);
    jbyteArray jisk = toJavaByteArray(env, isk, isk_len);

    // Construct io.github.denseidentity.bbsgroupsig.BBSSGS.SetupResult(byte[],byte[],byte[])
    jclass cls = env->FindClass("io/github/denseidentity/bbsgroupsig/BBSSGS$SetupResult");
    jmethodID ctor = env->GetMethodID(cls, "<init>", "([B[B[B)V");
    return env->NewObject(cls, ctor, jgpk, josk, jisk);
}

// byte[] bbs04_user_keygen(byte[] gpk, byte[] isk)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1user_1keygen(JNIEnv* env, jclass,
                                                                    jbyteArray jgpk,
                                                                    jbyteArray jisk) {
    jsize gpk_len = env->GetArrayLength(jgpk);
    std::vector<unsigned char> gpk_buf(gpk_len);
    env->GetByteArrayRegion(jgpk, 0, gpk_len, reinterpret_cast<jbyte*>(gpk_buf.data()));

    jsize isk_len = env->GetArrayLength(jisk);
    std::vector<unsigned char> isk_buf(isk_len);
    env->GetByteArrayRegion(jisk, 0, isk_len, reinterpret_cast<jbyte*>(isk_buf.data()));

    unsigned char* usk = nullptr;
    size_t usk_len = 0;
    if (bbs04_user_keygen_c(gpk_buf.data(), gpk_len,
                            isk_buf.data(), isk_len,
                            &usk, &usk_len) != BBSGS_OK) {
        throwJavaException(env, "bbs04_user_keygen_c failed");
        return nullptr;
    }
    return toJavaByteArray(env, usk, usk_len);
}

// byte[] bbs04_sign(byte[] gpk, byte[] usk, byte[] msg)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1sign(JNIEnv* env, jclass,
                                                            jbyteArray jgpk,
                                                            jbyteArray jusk,
                                                            jbyteArray jmsg) {
    jsize gpk_len = env->GetArrayLength(jgpk);
    std::vector<unsigned char> gpk_buf(gpk_len);
    env->GetByteArrayRegion(jgpk, 0, gpk_len, reinterpret_cast<jbyte*>(gpk_buf.data()));

    jsize usk_len = env->GetArrayLength(jusk);
    std::vector<unsigned char> usk_buf(usk_len);
    env->GetByteArrayRegion(jusk, 0, usk_len, reinterpret_cast<jbyte*>(usk_buf.data()));

    jsize msg_len = env->GetArrayLength(jmsg);
    std::vector<unsigned char> msg_buf(msg_len);
    env->GetByteArrayRegion(jmsg, 0, msg_len, reinterpret_cast<jbyte*>(msg_buf.data()));

    unsigned char* sig = nullptr;
    size_t sig_len = 0;
    if (bbs04_sign_c(gpk_buf.data(), gpk_len,
                     usk_buf.data(), usk_len,
                     msg_buf.data(), msg_len,
                     &sig, &sig_len) != BBSGS_OK) {
        throwJavaException(env, "bbs04_sign_c failed");
        return nullptr;
    }
    return toJavaByteArray(env, sig, sig_len);
}

// boolean bbs04_verify_usk(byte[] gpk, byte[] usk)
JNIEXPORT jboolean JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1verify_1usk(JNIEnv* env, jclass,
                                                                   jbyteArray jgpk,
                                                                   jbyteArray jusk) {
    jsize gpk_len = env->GetArrayLength(jgpk);
    std::vector<unsigned char> gpk_buf(gpk_len);
    env->GetByteArrayRegion(jgpk, 0, gpk_len, reinterpret_cast<jbyte*>(gpk_buf.data()));

    jsize usk_len = env->GetArrayLength(jusk);
    std::vector<unsigned char> usk_buf(usk_len);
    env->GetByteArrayRegion(jusk, 0, usk_len, reinterpret_cast<jbyte*>(usk_buf.data()));

    int ok = bbs04_verify_usk_c(gpk_buf.data(), gpk_len,
                                usk_buf.data(), usk_len);
    return (ok == 1) ? JNI_TRUE : JNI_FALSE;
}

// boolean bbs04_verify(byte[] gpk, byte[] sig, byte[] msg)
JNIEXPORT jboolean JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1verify(JNIEnv* env, jclass,
                                                              jbyteArray jgpk,
                                                              jbyteArray jsig,
                                                              jbyteArray jmsg) {
    jsize gpk_len = env->GetArrayLength(jgpk);
    std::vector<unsigned char> gpk_buf(gpk_len);
    env->GetByteArrayRegion(jgpk, 0, gpk_len, reinterpret_cast<jbyte*>(gpk_buf.data()));

    jsize sig_len = env->GetArrayLength(jsig);
    std::vector<unsigned char> sig_buf(sig_len);
    env->GetByteArrayRegion(jsig, 0, sig_len, reinterpret_cast<jbyte*>(sig_buf.data()));

    jsize msg_len = env->GetArrayLength(jmsg);
    std::vector<unsigned char> msg_buf(msg_len);
    env->GetByteArrayRegion(jmsg, 0, msg_len, reinterpret_cast<jbyte*>(msg_buf.data()));

    int ok = bbs04_verify_c(gpk_buf.data(), gpk_len,
                            sig_buf.data(), sig_len,
                            msg_buf.data(), msg_len);
    return (ok == 1) ? JNI_TRUE : JNI_FALSE;
}

// byte[] bbs04_open(byte[] gpk, byte[] osk, byte[] sig)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_bbs04_1open(JNIEnv* env, jclass,
                                                            jbyteArray jgpk,
                                                            jbyteArray josk,
                                                            jbyteArray jsig) {
    jsize gpk_len = env->GetArrayLength(jgpk);
    std::vector<unsigned char> gpk_buf(gpk_len);
    env->GetByteArrayRegion(jgpk, 0, gpk_len, reinterpret_cast<jbyte*>(gpk_buf.data()));

    jsize osk_len = env->GetArrayLength(josk);
    std::vector<unsigned char> osk_buf(osk_len);
    env->GetByteArrayRegion(josk, 0, osk_len, reinterpret_cast<jbyte*>(osk_buf.data()));

    jsize sig_len = env->GetArrayLength(jsig);
    std::vector<unsigned char> sig_buf(sig_len);
    env->GetByteArrayRegion(jsig, 0, sig_len, reinterpret_cast<jbyte*>(sig_buf.data()));

    unsigned char* cred = nullptr;
    size_t cred_len = 0;
    if (bbs04_open_c(gpk_buf.data(), gpk_len,
                     osk_buf.data(), osk_len,
                     sig_buf.data(), sig_len,
                     &cred, &cred_len) != BBSGS_OK) {
        throwJavaException(env, "bbs04_open_c failed");
        return nullptr;
    }
    return toJavaByteArray(env, cred, cred_len);
}

// byte[] ecScalarRandom()
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_ecScalarRandom(JNIEnv* env, jclass) {
    unsigned char* buf = nullptr;
    size_t len = 0;
    if (ec_scalar_random(&buf, &len) != BBSGS_OK) {
        throwJavaException(env, "ec_scalar_random failed");
        return nullptr;
    }
    return toJavaByteArray(env, buf, len);
}

// byte[] ecScalarInverse(byte[] scalar)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_ecScalarInverse(JNIEnv* env, jclass,
                                                                 jbyteArray jscalar) {
    jsize slen = env->GetArrayLength(jscalar);
    std::vector<unsigned char> s_buf(slen);
    env->GetByteArrayRegion(jscalar, 0, slen, reinterpret_cast<jbyte*>(s_buf.data()));

    unsigned char* inv = nullptr;
    size_t inv_len = 0;
    if (ec_scalar_inverse(s_buf.data(), slen, &inv, &inv_len) != BBSGS_OK) {
        throwJavaException(env, "ec_scalar_inverse failed");
        return nullptr;
    }
    return toJavaByteArray(env, inv, inv_len);
}

// byte[] ecG1HashToPoint(byte[] msg)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_ecG1HashToPoint(JNIEnv* env, jclass,
                                                                 jbyteArray jmsg) {
    jsize mlen = env->GetArrayLength(jmsg);
    std::vector<unsigned char> m_buf(mlen);
    env->GetByteArrayRegion(jmsg, 0, mlen, reinterpret_cast<jbyte*>(m_buf.data()));

    unsigned char* pt = nullptr;
    size_t pt_len = 0;
    if (ec_g1_hash_to_point(m_buf.data(), mlen, &pt, &pt_len) != BBSGS_OK) {
        throwJavaException(env, "ec_g1_hash_to_point failed");
        return nullptr;
    }
    return toJavaByteArray(env, pt, pt_len);
}

// byte[] ecG1Mul(byte[] point, byte[] scalar)
JNIEXPORT jbyteArray JNICALL
Java_io_github_denseidentity_bbsgroupsig_BBSSGS_ecG1Mul(JNIEnv* env, jclass,
                                                        jbyteArray jpoint,
                                                        jbyteArray jscalar) {
    jsize plen = env->GetArrayLength(jpoint);
    std::vector<unsigned char> p_buf(plen);
    env->GetByteArrayRegion(jpoint, 0, plen, reinterpret_cast<jbyte*>(p_buf.data()));

    jsize slen2 = env->GetArrayLength(jscalar);
    std::vector<unsigned char> s2_buf(slen2);
    env->GetByteArrayRegion(jscalar, 0, slen2, reinterpret_cast<jbyte*>(s2_buf.data()));

    unsigned char* out = nullptr;
    size_t out_len = 0;
    if (ec_g1_mul(p_buf.data(), plen, s2_buf.data(), slen2, &out, &out_len) != BBSGS_OK) {
        throwJavaException(env, "ec_g1_mul failed");
        return nullptr;
    }
    return toJavaByteArray(env, out, out_len);
}

} // extern "C"
