#include "sha1.h"
#include "digest-openssl.h"
#include <iostream>

namespace Erpiko {

class Sha1::Impl {
  DigestOpenSsl *d;
  public:
    Impl() : d(new DigestOpenSsl("1.3.14.3.2.26")) {}

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

Sha1::Sha1() :
 impl{std::make_unique<Impl>()} {
}

Sha1::~Sha1() = default;

void
Sha1::update(std::vector<unsigned char> data) {
  impl->update(data);
}

std::vector<unsigned char>
Sha1::finalize(std::vector<unsigned char> data) {
  return impl->finalize(data);
}

} // namespace Erpiko
