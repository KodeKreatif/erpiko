#include "erpiko/sha384.h"
#include "digest-openssl.h"
#include <iostream>

namespace Erpiko {

class Sha384::Impl {
  DigestOpenSsl *d;
  public:
    Impl() : d(new DigestOpenSsl("2.16.840.1.101.3.4.2.2")) {}

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

Sha384::Sha384() :
 impl{std::make_unique<Impl>()} {
}

Sha384::~Sha384() = default;

void
Sha384::update(std::vector<unsigned char> data) {
  impl->update(data);
}

std::vector<unsigned char>
Sha384::finalize(std::vector<unsigned char> data) {
  return impl->finalize(data);
}

} // namespace Erpiko
