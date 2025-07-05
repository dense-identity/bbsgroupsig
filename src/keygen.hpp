#ifndef BBSGS_SETUP_HPP
#define BBSGS_SETUP_HPP

#include "keys.hpp"

namespace bbsgs {

    void bbs04_setup(GroupPublicKey &gpk, OpenerSecretKey &osk, IssuerSecretKey &sk);
    UserSecretKey bbs04_user_keygen(IssuerSecretKey const &isk, GroupPublicKey const &gpk);

} // namespace bbsgs

#endif // BBSGS_SETUP_HPP
