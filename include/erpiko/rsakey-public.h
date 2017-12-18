#ifndef _RSA_PUBLIC_KEY_H_
#define _RSA_PUBLIC_KEY_H_

#include "erpiko/bigint.h"
#include "erpiko/oid.h"
#include <memory>
#include <vector>

namespace Erpiko {

class Token;
class RsaPublicKey {
  public:
    /**
     * Creates a new instance of RSA public key
     * @param token if exists, use the specified token
     */
    RsaPublicKey(Token *t = nullptr);
    virtual ~RsaPublicKey();

    /**
     * Gets the modulus of the public key
     * @return the modulus
     */
    const BigInt& modulus() const;

    /**
     * Gets the exponent of the public key
     * @return the exponent
     */
    const BigInt& exponent() const;

    /**
     * Imports a public RSA key from DER
     * @param der vector containing DER data
     * @return a new instance of RsaPublicKey
     */
    static RsaPublicKey* fromDer(const std::vector<unsigned char> der);

    /**
     * Imports a public RSA key from DER
     * @param der vector containing DER data
     * @return a new instance of RsaPublicKey
     */
    static RsaPublicKey* fromPem(const std::string pem);

    /**
     * Gets the PKCS#8 format as PEM string (if passphrase is given), otherwise
     * returns a traditional RSA format in encoded PEM
     * @param passphrase
     * @return string containing PEM. Empty if something is broken.
     */
    const std::string toPem() const;

    /**
     * Gets the PKCS#8 format as PEM string (if passphrase is given), otherwise
     * returns a traditional RSA format in encoded PEM
     * @param passphrase
     * @return string containing PEM. Empty if something is broken.
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Encrypts data using public key
     * @return encrypted data
     */
    const std::vector<unsigned char> encrypt(const std::vector<unsigned char> data) const;

    /**
     * Verifies data using public key
     * @return signature
     */
    bool verify(const std::vector<unsigned char> signature, const std::vector<unsigned char> data, const ObjectId& digest) const;


    /**
     * Enable token to be used in cryptography operations
     */
    void enableToken();

    /**
     * Disable token to be used in cryptography operations
     */
    void disableToken();



  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _RSA_PUBLIC_KEY_H_
