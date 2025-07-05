#include "keygen.hpp"

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

    UserSecretKey bbs04_user_keygen(IssuerSecretKey const &isk, GroupPublicKey const &gpk) {
        UserSecretKey usk;
        usk.x = ecgroup::Scalar::get_random();
        ecgroup::Scalar gamma_plus_x = ecgroup::Scalar::add(isk.gamma, usk.x);
        usk.A = ecgroup::G1Point::mul(gpk.g1, gamma_plus_x.inverse());
        return usk;
    }

} // namespace bbsgs