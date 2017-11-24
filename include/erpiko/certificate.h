#ifndef _CERTIFICATE_H_
#define _CERTIFICATE_H_

#include "erpiko/identity.h"
#include "erpiko/bigint.h"
#include "erpiko/time.h"
#include "erpiko/rsakey.h"
#include "erpiko/rsakey-public.h"
#include <string>
#include <memory>

namespace CertificateRevocationState {
enum State {
  UNKNOWN,
  REVOKED,
  NOT_REVOKED
};
}

namespace CertificateTrustState {
enum State {
  UNKNOWN,
  TRUSTED,
  NOT_TRUSTED
};
}


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

class CertificateExtension;
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
     * Creates a new Certificate from specified data
     * @param notBefore the start date
     * @param notAfter the end date
     * @param subjectIdentity the subject Identity
     * @param issuerIdentity the issuer Identity
     * @param serialNumber the serial number
     * @param publicKey the public key of the signer
     * @param signerKey the signer key
     */
    static Certificate* create(const Time& notBefore, const Time& notAfter, const Identity& subjectIdentity, const Identity& issuerIdentity, const BigInt& serialNumber, const RsaPublicKey& publicKey, const RsaKey& signerKey);

    /**
     * Creates a new Certificate from PEM data
     * @param pem PEM data
     * @return Certificate
     */
    static Certificate* fromPem(const std::string pem);

    /**
     * Exports the certificate to DER format
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Exports the certificate to PEM format
     * @return PEM string
     */
    const std::string toPem() const;

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
     * Gets the CRL distribution url of the certificate
     * @return the url string of the CRL distribution point
     */
    const std::string crlDistPoint() const;

    /**
     * Gets the certificate extensions
     * @return the vector containing the list of extension's pointers
     */
    const std::vector<const CertificateExtension*>& extensions() const;

    /**
     * Check against CRL
     * @param issuerDer Issuer certificate in DER
     * @param crlDer CRL certificate in DER
     * @return integer value 1 if the cert has been revoked. Otherwise, it hasn't.
     */
    CertificateRevocationState::State isRevoked(const std::vector<unsigned char> issuerDer, const std::vector<unsigned char> crlDer) const;

    /**
     * Verify trust against root CA certificate & CRL
     * @param rootCaDer Root CA certificate in DER
     * @param crlDer CRL certificate in DER
     * @param caChainPemPath Path of the certificate chain (in PEM)
     * @return integer value 1 if the cert is trusted by the issuer and certificate chain. Otherwise, it isn't trusted.
     */
    CertificateTrustState::State isTrusted(const std::vector<unsigned char> rootCaDer, const std::vector<unsigned char> crlDer, const std::string& caChainPemPath) const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _CERTIFICATE_H_
