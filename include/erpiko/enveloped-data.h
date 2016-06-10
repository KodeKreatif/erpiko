#ifndef _ENVELOPED_DATA_H_
#define _ENVELOPED_DATA_H_

#include "erpiko/oid.h"
#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include <string>
#include <memory>

namespace Erpiko {

/**
 * Handles EnvelopedData CMS data structure
 */
class EnvelopedData {
  public:
    /**
     * Creates a new EnvelopedData object
     * @param certificate the certificate of the decryptor
     * @param algorithm the algorithm used in encryption
     */
    EnvelopedData(const Certificate& certificate, const ObjectId& algorithm);

    /**
     * Parses DER data and returns an instance of EnvelopedData
     * @param der DER data
     * @return pointer to EnvelopedData
     */
    static EnvelopedData* fromDer(const std::vector<unsigned char> der);

    /**
     * Parses PEM data and returns an instance of EnvelopedData
     * @param pem PEM data
     * @param certificate the certificate of the signer
     * @return pointer to EnvelopedData
     */
    static EnvelopedData* fromPem(const std::string pem);

    /**
     * Exports EnvelopedData data to DER
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Exports EnvelopedData to PEM
     * @return EnvelopedData in PEM format
     */
    const std::string toPem() const;

    /**
     * Encrypt data
     * @param data The data to be encrypted
     * @param password The password used to encrypt the data
     */
    void encrypt(const std::vector<unsigned char> data);

    /**
     * Decyrpt an EnvelopedData
     * @param certificate the certificate of the decryptor
     * @param privateKey the private key of the decryptor
     */
    const std::vector<unsigned char> decrypt(const Certificate& certificate, const RsaKey& privateKey) const;

    virtual ~EnvelopedData();

  private:
    EnvelopedData();

    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _ENVELOPED_DATA_H_
