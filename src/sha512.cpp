#include "sha512.h"
#include "digest-openssl.h"
#include <iostream>

namespace Erpiko {

class Sha512::Impl {
  DigestOpenSsl *d;
  public:
    Impl() : d(new DigestOpenSsl("2.16.840.1.101.3.4.2.3")) {}

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

Sha512::Sha512() :
 impl{std::make_unique<Impl>()} {
}

Sha512::~Sha512() = default;

void
Sha512::update(std::vector<unsigned char> data) {
  impl->update(data);
}

std::vector<unsigned char>
Sha512::finalize(std::vector<unsigned char> data) {
  return impl->finalize(data);
}

} // namespace Erpiko
