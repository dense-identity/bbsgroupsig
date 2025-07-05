#include "setup.hpp"

namespace bbsgs {

    void bbs04_setup(GroupPublicKey &gpk, OpenerSecretKey &osk, IssuerSecretKey &isk) {
        gpk.g1 = ecgroup::G1Point::get_random();
        gpk.g2 = ecgroup::G2Point::get_random();
        gpk.h = ecgroup::G1Point::get_random();

        osk.xi1 = ecgroup::Scalar::get_random();
        osk.xi2 = ecgroup::Scalar::get_random();

        gpk.u = ecgroup::G1Point::mul(gpk.h, osk.xi1.inverse());
        gpk.v = ecgroup::G1Point::mul(gpk.h, osk.xi2.inverse());

        isk.gamma = ecgroup::Scalar::get_random();
        gpk.w = ecgroup::G2Point::mul(gpk.g2, isk.gamma);
    };

} // namespace bbsgs