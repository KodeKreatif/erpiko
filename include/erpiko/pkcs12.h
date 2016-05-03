#ifndef _PKCS12_H_
#define _PKCS12_H_

#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include <string>
#include <memory>

namespace Erpiko {

/**
 * Handles PKCS#12 data structure
 */
class Pkcs12 {
  public:
    /**
     * Creates a PKCS#12 data
     * @param label The string to label this PKCS#12 with
     * @param passphrase The passphrase to protect the data
     */
    Pkcs12(const std::string label, const std::string passphrase);

    /**
     * Parses PKCS#12 data and returns an instance of Pkcs12
     * @param der DER data
     * @param passphrase the passphrase to decrypt information in the PKCS#12 structure
     * @return pointer to Pkcs12
     */
    static Pkcs12* fromDer(const std::vector<unsigned char> der, const std::string passphrase);

    /**
     * Exports PKCS#12 data to DER
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Gets the private key embedded inside a PKCS#12 data
     * @return private key
     */
    const RsaKey& privateKey() const;

    /**
     * Adds a private key into PKCS#12
     * @param privateKey the private key to add
     */
    void privateKey(const RsaKey& privateKey);

    /**
     * Gets the certificate inside the PKCS#12
     * @return Certificate
     */
    const Certificate& certificate() const;

    /**
     * Adds a certificate into PKCS#12
     * @param cert The certificate to add
     */
    void certificate(const Certificate& cert);

    /**
     * Gets list of CA certificates chain
     * @return vector of certificate's pointer. Don't delete the pointer.
     */
    const std::vector<const Certificate*>& certificateChain() const;

    virtual ~Pkcs12();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _PKCS12_H_
