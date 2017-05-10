#ifndef _SIGNED_DATA_H_
#define _SIGNED_DATA_H_

#include "erpiko/oid.h"
#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include <string>
#include <memory>

namespace Erpiko {

/**
 * Handles SignedData CMS data structure
 */
class SignedData {
  public:
    /**
     * Creates a SignedData object
     * @param certificate the certificate of the signer
     * @param privateKey the private key of the signer
     * @param digestAlgorithmIdentifier the OID of the algorithm used to construct the digest
     */
    SignedData(const Certificate& certificate, const RsaKey& privateKey);

    /**
     * Parses DER data and returns an instance of SignedData
     * @param der DER data
     * @param certificate the certificate of the signer
     * @return pointer to SignedData
     */
    static SignedData* fromDer(const std::vector<unsigned char> der, const Certificate& certificate);

    /**
     * Parses PEM data and returns an instance of SignedData
     * @param pem PEM data
     * @param certificate the certificate of the signer
     * @return pointer to SignedData
     */
    static SignedData* fromPem(const std::string pem, const Certificate& certificate);

    /**
     * Parses S/MIME data and returns an instance of SignedData
     * @param pem S/MIME data
     * @param certificate the certificate of the signer
     * @return pointer to SignedData
     */
    static SignedData* fromSMime(const std::string pem, const Certificate& certificate);

    /**
     * Exports SignedData data to DER
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Exports SignedData to PEM
     * @return SignedData in PEM format
     */
    const std::string toPem() const;

    /**
     * Signs the SignedData and prepare a detached SignedData structure.
     * After the data is signed, no more update() and signDetached() or sign() functions can be called
     */
    void signDetached();

    /**
     * Signs the SignedData and prepare a detached SignedData structure.
     * After the data is signed, no more update() and signDetached() or sign() functions can be called
     */
    void sign();

    /**
     * Signs the SignedData in S/MIME mode. Data can be always updated with update API, and
     * the final S/MIME structure and data is finalized with toSMime() call.
     */
    void signSMime() const;

    /**
     * Gets the S/MIME representation of the structure and data. This call only makes sense
     * when it is preceeded by a signSMime call
     */
    const std::string toSMime() const;

    /**
     * Initiates the retrieval of the S/MIME representation of the structure and data. This call only makes sense
     * when it is preceeded by a signSMime call
     */
    void toSMime(std::function<void(std::string)> onData, std::function<void(void)> onEnd) const;

    /**
     * Updates data to be signed or to be verified
     */
    void update(const unsigned char* data, const size_t length);

    /**
     * Updates data to be signed or to be verified
     */
    void update(const std::vector<unsigned char> data);

    /**
     * Verifies a SignedData
     */
    bool verify() const;


    /**
     * Whether the SignedData is detached or not
     * @return whether the SignedData is detached
     */
    bool isDetached() const;

    virtual ~SignedData();

  private:
    SignedData();
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _SIGNED_DATA_H_
