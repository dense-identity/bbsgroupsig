#include "bbsgs/bbsgs.hpp"

namespace bbsgs {
    void setup(GroupPublicKey &gpk, OpenerSecretKey &osk, IssuerSecretKey &sk) {
        gpk.g1 = ecgroup::G1Point::get_random();
        gpk.g2 = ecgroup::G2Point::get_random();
    }
}