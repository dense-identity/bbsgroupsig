#ifndef JODI_UTILS_HPP
#define JODI_UTILS_HPP

#include "base.hpp"

namespace bbsgs {
    class Utils {
        public:
            Utils();
            static string BytesToString(Bytes const & data);
            static Bytes StringToBytes(string const & data);

            static Bytes Sha160(Bytes const & preimage);
            static Bytes Sha256(Bytes const & preimage);

            static string EncodeBase64(Bytes const & data);
            static Bytes DecodeBase64(string const & data);

            static Bytes Xor(Bytes const & x, Bytes const & y);
            static Bytes RemoveTrailingZeroes(Bytes & data);

            static Bytes RandomBytes(size_t size);
    };
}

#endif // JODI_UTILS_HPP
