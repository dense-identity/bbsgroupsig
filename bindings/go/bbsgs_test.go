package bbsgs

import "testing"

func TestBBS04EndToEnd(t *testing.T) {
    InitPairing()

    gpk, osk, isk, err := Setup()
    if err != nil || len(gpk) == 0 || len(osk) == 0 || len(isk) == 0 {
        t.Fatalf("Setup failed or returned empty: %v", err)
    }

    usk, err := UserKeygen(gpk, isk)
    if err != nil || len(usk) == 0 {
        t.Fatalf("UserKeygen failed or returned empty: %v", err)
    }

    if !VerifyUsk(gpk, usk) {
        t.Fatal("VerifyUsk returned false")
    }

    msg := []byte("hello")
    sig, err := Sign(gpk, usk, msg)
    if err != nil || len(sig) == 0 {
        t.Fatalf("Sign failed or returned empty: %v", err)
    }

    if !Verify(gpk, sig, msg) {
        t.Fatal("Verify returned false")
    }

    credA, err := Open(gpk, osk, sig)
    if err != nil || len(credA) == 0 {
        t.Fatalf("Open failed or returned empty: %v", err)
    }
}
