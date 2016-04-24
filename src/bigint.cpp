#include "erpiko/bigint.h"
#include "openssl/bn.h"

namespace Erpiko {

class BigInt::Impl {
    BIGNUM* bn;

  public:
    Impl() {
      bn = BN_new();
    }

    ~Impl() {
      BN_free(bn);
    }
};

BigInt::BigInt() : impl{std::make_unique<Impl>()} {
}

BigInt::~BigInt() = default;

} // namespace Erpiko
