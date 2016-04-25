#include "erpiko/identity.h"
#include <openssl/x509.h>

namespace Erpiko {

class Identity::Impl {

  public:
    Impl() {
    }

    virtual ~Impl() {
  }
};

Identity::Identity() : impl{std::make_unique<Impl>()} {
}

Identity::~Identity() {
}

} // namespace Erpiko
