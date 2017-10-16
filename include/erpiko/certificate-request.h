#ifndef _CERTIFICATE_REQUEST_H_
#define _CERTIFICATE_REQUEST_H_

#include "erpiko/identity.h"
#include "erpiko/rsakey.h"
#include "erpiko/rsakey-public.h"
#include <memory>
namespace Erpiko {

class CertificateRequest {
  private:
    /**
     * Private constructor
     */
    CertificateRequest();

  public:
    /**
     * Creates a new instance of CertificateRequest
     * @param subject the subject's identity
     * @param key the subject's key
     * @param algorithm the signing algorithm
     */
    CertificateRequest(const Identity& subject, const RsaKey& key, const ObjectId& algorithm);

    /**
     * Destructs an instance of CertificateRequest
     */
    virtual ~CertificateRequest();

    /**
     * Exports the signed certificate request to PEM format
     * @return PEM string
     */
    const std::string toPem() const;

    /**
     * Exports the signed certificate request to DER format
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Creates a new CertificateRequest from DER data
     * @param der DER data
     * @return CertificateRequest
     */
    static CertificateRequest* fromDer(const std::vector<unsigned char> der);

    /**
     * Creates a new CertificateRequest from PEM data
     * @param pem PEM data
     * @return CertificateRequest
     */
    static CertificateRequest* fromPem(const std::string pem);

    /**
     * Checks whether the signed certificate request is valid or not
     */
    bool isValid() const;

    /**
     * Gets the subject's Identity
     * @return identity
     */
    const Identity& subject() const;

    /**
     * Gets the public key
     * @return RsaPublicKey
     */
    const RsaPublicKey& publicKey() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif //  _CERTIFICATE_REQUEST_H_
