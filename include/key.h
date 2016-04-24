#ifndef _KEY_H_
#define _KEY_H_

#include <memory>
#include <vector>

namespace Erpiko {

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

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _KEY_H_
