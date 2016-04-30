#ifndef _CERTIFICATE_EXTENSION_H_
#define _CERTIFICATE_EXTENSION_H_

#include "erpiko/certificate.h"
#include "erpiko/oid.h"
#include <string>
#include <memory>

namespace Erpiko {

/**
 * Certificate extension
 */
class CertificateExtension {
  public:
    virtual const ObjectId& objectId() const = 0;
};

class CertificateSubjectKeyIdentifierExtension : public CertificateExtension {
  friend class Certificate;
  public:
    const std::vector<unsigned char> value() const;
    virtual const ObjectId& objectId() const;
  private:
    CertificateSubjectKeyIdentifierExtension(std::vector<unsigned char> der);
    class Impl;
    std::unique_ptr<Impl> impl;

};

} // namespace Erpiko
#endif // _CERTIFICATE_EXTENSION_H_
