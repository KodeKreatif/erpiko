#include "erpiko/bigint.h"
#include "openssl/bn.h"

namespace Erpiko {

class BigInt::Impl {
  public:
    BIGNUM* bn;

    Impl() {
      bn = BN_new();
    }

    ~Impl() {
      BN_free(bn);
    }
};

BigInt::BigInt() : impl{std::make_unique<Impl>()} {
}

BigInt::BigInt(unsigned long value) : impl{std::make_unique<Impl>()} {
  BN_set_word(impl->bn, value);
}

BigInt* BigInt::fromString(const std::string string) {
  BigInt* b = new BigInt();
  int ret;
  if (string.substr(0, 2) == "0x") {
    ret = BN_hex2bn(&b->impl->bn, string.c_str() + 2); // 2 bytes offset
  } else {
    ret = BN_dec2bn(&b->impl->bn, string.c_str());
  }
  if (ret == 0) {
    delete(b);
    return nullptr;
  }
  return b;
}

BigInt::~BigInt() = default;

bool BigInt::operator==(const BigInt& other) {
  return (BN_ucmp(impl->bn, other.impl->bn) == 0);
}



} // namespace Erpiko
