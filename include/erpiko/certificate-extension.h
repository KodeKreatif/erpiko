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
    /**
     * Gets the object id of the extension
     * @return the object id
     */
    virtual const ObjectId& objectId() const = 0;

    /**
     * Gets the criticality of the extension
     * @return the criticality value
     */
    virtual bool critical() const = 0;
};

/**
 * Subject Key Identifier certificate extension
 */
class CertificateSubjectKeyIdentifierExtension : public CertificateExtension {
  friend class Certificate;
  public:
    /**
     * Gets the subject key identifier value
     * @return the value as vector of bytes
     */
    const std::vector<unsigned char> value() const;
    virtual const ObjectId& objectId() const;
    virtual bool critical() const;
  private:
    CertificateSubjectKeyIdentifierExtension(const bool critical, std::vector<unsigned char> der);
    class Impl;
    std::unique_ptr<Impl> impl;

};

/**
 * Basic Constraints certificate extension
 */
class CertificateBasicConstraintsExtension : public CertificateExtension {
  friend class Certificate;
  public:
    /**
     * Gets the information whether the subject certificate is a CA certificate or not
     * @return whether the subject certificate is CA
     */
    bool isCa() const;

    /**
     * Gets the maximum validation path
     * @return the maximum validation path
     */
    unsigned int pathLengthConstraints() const;

    virtual const ObjectId& objectId() const;
    virtual bool critical() const;
  private:
    CertificateBasicConstraintsExtension(const bool critical, std::vector<unsigned char> der);
    class Impl;
    std::unique_ptr<Impl> impl;

};


} // namespace Erpiko
#endif // _CERTIFICATE_EXTENSION_H_
