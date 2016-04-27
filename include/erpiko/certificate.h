#ifndef _CERTIFICATE_H_
#define _CERTIFICATE_H_

#include "erpiko/identity.h"
#include "erpiko/bigint.h"
#include "erpiko/time.h"
#include "erpiko/rsakey-public.h"
#include <string>
#include <memory>

namespace Erpiko {

/**
 * X509 Key Usage
 */
  enum class KeyUsage {
    DIGITAL_SIGNATURE = 0x80,
    NON_REPUDIATION = 0x40,
    KEY_ENCIPHERMENT = 0x20,
    DATA_ENCIPHERMENT = 0x10,
    KEY_AGREEMENT = 0x8,
    KEY_CERT_SIGN =0x4,
    CRL_SIGN = 0x2,
    ENCIPHER_ONLY = 0x1,
    DECIPHER_ONLY = 0x8000
  };

/**
 * X509 Key Extended Usage
 */
  enum class ExtendedKeyUsage {
    SSL_SERVER = 0x1,
    SSL_CLIENT = 0x2,
    SMIME = 0x4,
    CODE_SIGN = 0x8,
    SGC = 0x8,
    OCSP_SIGN = 0x10,
    TIMESTAMP = 0x40,
    DVCS = 0x80,
  };

/**
 * X509 certificate
 */

class Certificate {
  public:
    Certificate();
    virtual ~Certificate();

    /**
     * Creates a new Certificate from DER data
     * @param der DER data
     * @return Certificate
     */
    static Certificate* fromDer(const std::vector<unsigned char> der);

    /**
     * Gets the identity of the subject
     * @return identity of the subject
     */
    const Identity& subjectIdentity() const;

    /**
     * Gets the identity of the issuer
     * @return identity of the issuer
     */
    const Identity& issuerIdentity() const;

    /**
     * Gets serial number
     * @return serial number
     */
    const BigInt& serialNumber() const;

    /**
     * Gets the public key
     * @return the public key
     */
    const RsaPublicKey& publicKey() const;


    /**
     * Gets key usage
     * @return key usage
     */
    KeyUsage keyUsage() const;

    /**
     * Gets extended key usage
     * @return extended key usage
     */
    ExtendedKeyUsage extendedKeyUsage() const;

    /**
     * Gets the validity of the certificate
     * @return time of the first moment the certificate is valid
     */
    const Time& notBefore() const;

    /**
     * Gets the validity of the certificate
     * @return time of the last moment the certificate is valid
     */
    const Time& notAfter() const;

    /**
     * Gets the subject key identifier
     * @return Reference to the subject key identifier
     */
    const std::vector<unsigned char>& subjectKeyIdentifier();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _CERTIFICATE_H_
