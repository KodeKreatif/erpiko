#include "erpiko/sha224.h"
#include "digest-openssl.h"
#include <iostream>

namespace Erpiko {

class Sha224::Impl {
  DigestOpenSsl *d;
  public:
    Impl() : d(new DigestOpenSsl("2.16.840.1.101.3.4.2.4")) {}

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

Sha224::Sha224() :
 impl{std::make_unique<Impl>()} {
}

Sha224::~Sha224() = default;

void
Sha224::update(std::vector<unsigned char> data) {
  impl->update(data);
}

std::vector<unsigned char>
Sha224::finalize(std::vector<unsigned char> data) {
  return impl->finalize(data);
}

} // namespace Erpiko
