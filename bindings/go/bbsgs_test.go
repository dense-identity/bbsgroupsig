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

    // EC helper tests
    // ScalarRandom
    scalar, err := ScalarRandom()
    if err != nil || len(scalar) == 0 {
        t.Fatalf("ScalarRandom failed or returned empty: %v", err)
    }

    // ScalarInverse
    inv, err := ScalarInverse(scalar)
    if err != nil || len(inv) == 0 {
        t.Fatalf("ScalarInverse failed or returned empty: %v", err)
    }

    // Hash to G1 point
    point, err := G1HashToPoint(msg)
    if err != nil || len(point) == 0 {
        t.Fatalf("G1HashToPoint failed or returned empty: %v", err)
    }

    // G1 multiplication: P * scalar
    mulP, err := G1Mul(point, scalar)
    if err != nil || len(mulP) == 0 {
        t.Fatalf("G1Mul failed or returned empty: %v", err)
    }

    // Multiply the result by the inverse: should get back original point
    roundTrip, err := G1Mul(mulP, inv)
    if err != nil || len(roundTrip) == 0 {
        t.Fatalf("G1Mul inverse failed: %v", err)
    }

    if !equalBytes(point, roundTrip) {
        t.Fatal("Round-trip multiplication did not return original point")
    }
}

// equalBytes is a helper to compare two byte slices
func equalBytes(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
