#include "erpiko/certificate.h"
#include <openssl/x509.h>

namespace Erpiko {

class Certificate::Impl {
  X509* x509;

  public:
    Impl() {
      x509 = X509_new();
    }

    virtual ~Impl() {
      X509_free(x509);
      x509 = nullptr;
    }
};

Certificate::Certificate() : impl{std::make_unique<Impl>()} {
}

Certificate::~Certificate() {
}

} // namespace Erpiko
