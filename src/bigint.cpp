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

const std::string BigInt::toHexString() const {
  std::string retval;

  retval = BN_bn2hex(impl->bn);
  return retval;
}

BigInt::~BigInt() = default;

void BigInt::operator=(const BigInt& other) {
  BN_copy(impl->bn, other.impl->bn);
}


void BigInt::operator=(const unsigned long value) {
  BN_set_word(impl->bn, value);
}

void BigInt::operator=(const std::string string) {
  BIGNUM* other;
  other = BN_new();

  int ret;
  if (string.substr(0, 2) == "0x") {
    ret = BN_hex2bn(&other, string.c_str() + 2); // 2 bytes offset
  } else {
    ret = BN_dec2bn(&other, string.c_str());
  }

  if (ret) {
    BN_copy(impl->bn, other);
  }
  BN_free(other);

}

bool BigInt::operator==(const BigInt& other) const {
  return (BN_ucmp(impl->bn, other.impl->bn) == 0);
}



} // namespace Erpiko
