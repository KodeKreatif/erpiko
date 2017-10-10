#ifndef _SIGNED_DATA_H_
#define _SIGNED_DATA_H_

#include "erpiko/oid.h"
#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include <string>
#include <memory>
#include <functional>

namespace SigningType {
enum Value {
    DEFAULT,
    TEXT,
    NODETACH
};
}

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
     * Parses S/MIME data and returns an instance of SignedData
     * @param pem S/MIME data
     * @return pointer to SignedData
     */
    static SignedData* fromSMime(const std::string pem);

    /**
     * Initiate empty SignedData. This should be updated and finalized later.
     * Any chunk of data that throwed into this instance will be collected in memory
     * and the real operation will done by fromSMimeFinalize()
     * @param smimePartial  chunk of S/MIME data
     * @return pointer to SignedData
     */
    static SignedData* fromSMimeInit(const std::string smimePartial);

    /**
     * Update existing SignedData instance. This should be finalized later.
     * Any chunk of data that throwed into this instance will be collected in memory
     * If all the chunk of data has been imported, this should be finished with fromSMimeFinalize()
     * @param smimePartial  chunk of S/MIME data
     * @return pointer to SignedData
     */
    void fromSMimeUpdate(const std::string smimePartial);

    /**
     * Finalize the SignedData that came from fromSMimeInit.
     */
    void fromSMimeFinalize();

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
     * when it is preceeded by a signSMime call. This is overloading function with type parameter added.
     */
    void toSMime(std::function<void(std::string)> onData, std::function<void(void)> onEnd, SigningType::Value type) const;

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

    /**
     * Returns a vector of certificates enclosed in the signed data
     * @return vector of Certificates
     */
    std::vector<const Certificate*> certificates() const;

    /**
     * Returns the encrypted digest from the specified signer
     * @param index the index of the signer, default is 0
     * @return The digest
     */
    std::vector<unsigned char> digest(unsigned int index = 0) const;

    virtual ~SignedData();

  private:
    SignedData();
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _SIGNED_DATA_H_
