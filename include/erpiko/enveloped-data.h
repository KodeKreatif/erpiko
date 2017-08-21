#ifndef _ENVELOPED_DATA_H_
#define _ENVELOPED_DATA_H_

#include "erpiko/oid.h"
#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include <string>
#include <memory>
#include <functional>

namespace EncryptingType {
enum Value {
    DEFAULT,
    TEXT,
    BINARY
};
}

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
     * Parses S/MIME data and returns an instance of EnvelopedData
     * @param pem S/MIME data
     * @return pointer to EnvelopedData
     */
    static EnvelopedData* fromSMime(const std::string pem);
    
    /**
     * Initiate empty EnvelopedData. This should be updated and finalized later.
     * Any chunk of data that throwed into this instance will be collected in memory
     * and the real operation will done by fromSMimeFinalize()
     * @param smimePartial  chunk of S/MIME data
     * @return pointer to EnvelopedData
     */
    static EnvelopedData* fromSMimeInit(const std::string smimePartial);
    
    /**
     * Update existing EnvelopedData instance. This should be finalized later.
     * Any chunk of data that throwed into this instance will be collected in memory
     * If all the chunk of data has been imported, this should be finished with fromSMimeFinalize()
     * @param smimePartial  chunk of S/MIME data
     * @return pointer to EnvelopedData
     */
    void fromSMimeUpdate(const std::string smimePartial);

    /**
     * Finalize the EnvelopedData that came from fromSMimeInit.
     */
    void fromSMimeFinalize();
    
    /**
     * Parses S/MIME plain text file and returns an instance of EnvelopedData
     * @param pem S/MIME data
     * @return pointer to EnvelopedData
     */
    static EnvelopedData* fromSMimeFile(const std::string path);


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
     */
    void encrypt(const std::vector<unsigned char> data);

    /**
     * Decyrpt an EnvelopedData
     * @param certificate the certificate of the decryptor
     * @param privateKey the private key of the decryptor
     */
    const std::vector<unsigned char> decrypt(const Certificate& certificate, const RsaKey& privateKey) const;

    /**
     * Decyrpt an EnvelopedData
     * @param onData function that called when there is a chunk of data that still streamed 
     * @param onEnd function that called when the stream is ended
     * @param certificate the certificate of the decryptor
     * @param privateKey the private key of the decryptor
     */
    void decrypt(std::function<void(std::string)> onData, std::function<void(void)> onEnd, const Certificate& certificate, const RsaKey& privateKey) const;

    /**
     * Encrypts the EnvelopedData in S/MIME mode. Data can be always updated with update API, and
     * the final S/MIME structure and data is finalized with toSMime() call.
     * @param data The data to be encrypted
     * @param type Type of the data that will be encrypted. See EncryptingType namespace for enum values.
     */
    void encryptSMime(const std::vector<unsigned char> data, EncryptingType::Value type);

    /**
     * Update the data in EnvelopedData S/MIME mode. Operation is finalized with finalizeEncryptSMime() call.
     * @param data The data to be encrypted
     */
    void updateSMime(const std::vector<unsigned char> data);

    /**
     * Finalize and encrypt the EnvelopedData in S/MIME mode.
     * @param data The data to be encrypted
     * @param type Type of the data that will be encrypted. See EncryptingType namespace for enum values.
     */
    void finalizeEncryptSMime(const std::vector<unsigned char> data, EncryptingType::Value type);

    /**
     * Finalize and encrypt the EnvelopedData in S/MIME mode.
     * @param type Type of the data that will be encrypted. See EncryptingType namespace for enum values.
     */
    void finalizeEncryptSMime(EncryptingType::Value type);

    /**
     * Gets the S/MIME representation of the structure and data. This call only makes sense
     * when it is preceeded by a encryptSMime call
     * The additional parameter is EncryptingType. See EncryptingType namespace for
     * enumeratin values.
     */
    const std::string toSMime() const;
    
    const std::string toSMime(EncryptingType::Value type) const;
    
    /**
     * Initiates the retrieval of the S/MIME representation of the structure and data. This call only makes sense
     * when it is preceeded by a signSMime call
     * @param type See EncryptingType namespace for enumeration values.
     */
    void toSMime(std::function<void(std::string)> onData, std::function<void(void)> onEnd, EncryptingType::Value type) const;


    /**
     * Appends certificate to recipient list of the encrypted data
     *
     * @param certificate the certificate of the recipient
     */
    void addRecipient(const Certificate& certificate);

    virtual ~EnvelopedData();

  private:
    EnvelopedData();

    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _ENVELOPED_DATA_H_
