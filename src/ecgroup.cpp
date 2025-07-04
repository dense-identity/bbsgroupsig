#include "ecgroup.hpp"
#include "utils.hpp" // For base64 encoding/decoding

namespace bbsgs {

    void Init() {
        mcl::bn::initPairing();
    }
}