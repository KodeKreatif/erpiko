#include "key.h"
#include <openssl/rsa.h>

namespace Erpiko {

class RsaKey::Impl {
  public:
    RSA* rsa;
    unsigned int bits = 0;
    int ret;

    Impl() {
      rsa = RSA_new();
    }

    virtual ~Impl() {
      RSA_free(rsa);
    }

    void createKey(const unsigned int bits) {
      unsigned long e = RSA_F4;
      BIGNUM* bne = BN_new();
      ret = BN_set_word(bne, e);
      if (ret != 1) {
        return;
      }
      ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
      if (ret != 1) {
        BN_free(bne);
        return;
      }
      BN_free(bne);
      this->bits = bits;
    }
};

RsaKey::~RsaKey() = default;

RsaKey::RsaKey() : impl{std::make_unique<Impl>()} {
}

RsaKey* RsaKey::create(const unsigned int bits) {
  RsaKey* rsa = new RsaKey();

  rsa->impl->createKey(bits);
  if (bits == rsa->impl->bits) {
    return rsa;
  } else {
    return nullptr;
  }
}

unsigned int RsaKey::bits() const {
  return impl->bits;
}

} // namespace Erpiko
