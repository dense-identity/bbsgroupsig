// cgo.go
package bbsgs

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../build/src -lbbsgs_c_interface -lbbsgs -lecgroup -lmcl -lstdc++
#include "bbsgs/bbsgs_c.h"
#include <stdlib.h>
*/
import "C"
import (
    "errors"
    "unsafe"
)

// InitPairing wraps bbs04_init_pairing. Must be called before any other call.
func InitPairing() {
    C.bbs04_init_pairing()
}

// Setup generates the public key, opener SK, and issuer SK.
func Setup() (gpk, osk, isk []byte, err error) {
    var (
        gpkPtr  *C.uchar
        gpkLen  C.size_t
        oskPtr  *C.uchar
        oskLen  C.size_t
        iskPtr  *C.uchar
        iskLen  C.size_t
    )
    ret := C.bbs04_setup_c(
        &gpkPtr, &gpkLen,
        &oskPtr, &oskLen,
        &iskPtr, &iskLen,
    )
    if ret != 0 {
        err = errors.New("bbs04_setup_c failed")
        return
    }
    defer C.free_byte_buffer((*C.uchar)(gpkPtr))
    defer C.free_byte_buffer((*C.uchar)(oskPtr))
    defer C.free_byte_buffer((*C.uchar)(iskPtr))

    // Copy into Go slices
    gpk = C.GoBytes(unsafe.Pointer(gpkPtr), C.int(gpkLen))
    osk = C.GoBytes(unsafe.Pointer(oskPtr), C.int(oskLen))
    isk = C.GoBytes(unsafe.Pointer(iskPtr), C.int(iskLen))
    return
}

// UserKeygen derives a user secret key from gpk and isk.
func UserKeygen(gpk, isk []byte) (usk []byte, err error) {
    var (
        uskPtr *C.uchar
        uskLen C.size_t
    )
    ret := C.bbs04_user_keygen_c(
        (*C.uchar)(unsafe.Pointer(&gpk[0])), C.size_t(len(gpk)),
        (*C.uchar)(unsafe.Pointer(&isk[0])), C.size_t(len(isk)),
        &uskPtr, &uskLen,
    )
    if ret != 0 {
        err = errors.New("bbs04_user_keygen_c failed")
        return
    }
    defer C.free_byte_buffer(uskPtr)
    usk = C.GoBytes(unsafe.Pointer(uskPtr), C.int(uskLen))
    return
}

// Sign produces a group signature over msg.
func Sign(gpk, usk, msg []byte) (sig []byte, err error) {
    var (
        sigPtr *C.uchar
        sigLen C.size_t
    )
    ret := C.bbs04_sign_c(
        (*C.uchar)(unsafe.Pointer(&gpk[0])), C.size_t(len(gpk)),
        (*C.uchar)(unsafe.Pointer(&usk[0])), C.size_t(len(usk)),
        (*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
        &sigPtr, &sigLen,
    )
    if ret != 0 {
        err = errors.New("bbs04_sign_c failed")
        return
    }
    defer C.free_byte_buffer(sigPtr)
    sig = C.GoBytes(unsafe.Pointer(sigPtr), C.int(sigLen))
    return
}

// Verify returns true if sig is a valid signature on msg under gpk.
func Verify(gpk, sig, msg []byte) bool {
    ret := C.bbs04_verify_c(
        (*C.uchar)(unsafe.Pointer(&gpk[0])), C.size_t(len(gpk)),
        (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
        (*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
    )
    return ret == 1
}

// Open reveals the signer’s credential A from sig.
func Open(gpk, osk, sig []byte) (credA []byte, err error) {
    var (
        credPtr *C.uchar
        credLen C.size_t
    )
    ret := C.bbs04_open_c(
        (*C.uchar)(unsafe.Pointer(&gpk[0])), C.size_t(len(gpk)),
        (*C.uchar)(unsafe.Pointer(&osk[0])), C.size_t(len(osk)),
        (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
        &credPtr, &credLen,
    )
    if ret != 0 {
        err = errors.New("bbs04_open_c failed")
        return
    }
    defer C.free_byte_buffer(credPtr)
    credA = C.GoBytes(unsafe.Pointer(credPtr), C.int(credLen))
    return
}
