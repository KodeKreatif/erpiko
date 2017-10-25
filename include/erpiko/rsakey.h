#ifndef _RSA_KEY_H_
#define _RSA_KEY_H_

#include "erpiko/rsakey-public.h"
#include "erpiko/oid.h"
#include <memory>
#include <vector>

namespace Erpiko {
namespace RsaAlgorithmConstants {
  const char* const RSA_SHA256 = "1.2.840.113549.1.1.11";
  const char* const RSA_SHA1 = "1.2.840.113549.1.1.5";
} // namespace RsaAlgorithmConstants

class RsaKey {
  public:
    /**
     * Creates a new instance of RSA key
     */
    RsaKey();
    virtual ~RsaKey();

    /**
     * Creates a new RsaKey pair
     * @param bits number of bits
     * @return a new instance of RsaKey initialized to the number of bits as specified
     */
    static RsaKey* create(const unsigned int bits);

    /**
     * Imports a pair of RsaKey from PEM
     * @param pem string containing PEM data
     * @param passphrase the passphrase to import the PEM
     * @return a new instance of RsaKey
     */
    static RsaKey* fromPem(const std::string pem, const std::string passphrase = "");

    /**
     * Imports a pair of RsaKey from DER
     * @param der vector containing DER data
     * @param passphrase the passphrase to import the DER
     * @return a new instance of RsaKey
     */
    static RsaKey* fromDer(const std::vector<unsigned char> der, const std::string passphrase = "");

    /**
     * Gets the number of bits of this key
     * @return number of bits
     */
    unsigned int bits() const;

    /**
     * Gets the PKCS#8 format as PEM string (if passphrase is given), otherwise
     * returns a traditional RSA format in encoded PEM
     * @param passphrase
     * @return string containing PEM. Empty if something is broken.
     */
    const std::string toPem(const std::string passphrase = "") const;

    /**
     * Gets the PKCS#8 format as PEM string (if passphrase is given), otherwise
     * returns a traditional RSA format in encoded PEM
     * @param passphrase
     * @return string containing PEM. Empty if something is broken.
     */
    const std::vector<unsigned char> toDer(const std::string passphrase = "") const;

    /**
     * Gets public key out of the private key
     * @return public key reference
     */
    const RsaPublicKey& publicKey() const;

    /**
     * Decrypts data using private key
     * @return encrypted data
     */
    const std::vector<unsigned char> decrypt(const std::vector<unsigned char> data) const;

    /**
     * Signs data using private key
     * @return signature
     */
    const std::vector<unsigned char> sign(const std::vector<unsigned char> data, const ObjectId& digest) const;

    /**
     * Checks whether the key resides on device or not. If the key is generated on device using Token
     * object, then the key is on device and can't be exported.
     */
    bool onDevice() const;
  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _RSA_KEY_H_
