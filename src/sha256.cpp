#include "erpiko/sha256.h"
#include "digest-openssl.h"
#include <iostream>

namespace Erpiko {

class Sha256::Impl {
  DigestOpenSsl *d;
  public:
    Impl() : d(new DigestOpenSsl("2.16.840.1.101.3.4.2.1")) {}

    ~Impl() {
      delete d;
    }

    void update(std::vector<unsigned char> data) {
      d->update(data);
    }

    std::vector<unsigned char>
    finalize(std::vector<unsigned char> data) {
      return d->finalize(data);
    }
};

Sha256::Sha256() :
 impl{std::make_unique<Impl>()} {
}

Sha256::~Sha256() = default;

void
Sha256::update(std::vector<unsigned char> data) {
  impl->update(data);
}

std::vector<unsigned char>
Sha256::finalize(std::vector<unsigned char> data) {
  return impl->finalize(data);
}

} // namespace Erpiko
