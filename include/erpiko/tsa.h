#ifndef _TSA_H_
#define _TSA_H_
#include "erpiko/oid.h"
#include "erpiko/rsakey.h"
#include "erpiko/certificate.h"
#include "erpiko/signed-data.h"
#include <vector>
#include <memory>
#include <functional>

namespace Erpiko {

/**
 * TsaRequest class
 */
class TsaRequest {
  public:
    /**
     * Constructor
     * @param hashAlgorithm the hash algorithm used to generate the digest
     */
    TsaRequest(const ObjectId& hashAlgorithm);

    /**
     * Sets policyId of the request
     * @param policyId the policy id
     */
    void setPolicyId(const ObjectId& policyId);

    /**
     * Indicate whether the response must include server certificate
     * @param status whether the server certificate is required
     */
    void setIncludeCertificate(bool status);

    /**
     * Sets the request whether nonce is generated
     * @param status whether nonce is generated
     */
    void setNoNonce(bool status);

    /**
     * Indicates whether server certificate is required in the response
     * @returns whether server certificate is required
     */
    bool includeCertificate() const;

    /**
     * Returns whether nonce is enabled
     * @returns whether nonce is enabled
     */
    bool noNonce() const;

    /**
     * Gets the optional policy id of the request.
     * Returns an object id of "0.0.0.0" if there was no policy set before
     * @returns object id of the policy
     */
    const ObjectId& policyId() const;

    /**
     * Updates data to be hashed
     * @param data data to be hashed
     * @param length the length of the data
     */
    void update(const unsigned char* data, const size_t length);

    /**
     * Updates data to be hashed
     * @param data data to be hashed
     */
    void update(const std::vector<unsigned char> data);

    /**
     * Gets the representation of the request in DER format
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer();

    /**
     * Creates a new TsaRequest from DER data
     * @param der DER data
     * @return TsaRequest
     */
    static TsaRequest* fromDer(const std::vector<unsigned char> der);


    /**
     * Returns nonce value (if set)
     * @returns nonce value
     */
    const BigInt& nonceValue() const;

    /**
     * Returns hash algorithm used for the creating the digest
     * @return hash algoritm
     */
    const ObjectId& hashAlgorithm() const;

    /**
     * Returns digest of the request
     * @return digest
     */
    std::vector<unsigned char> digest() const;

    virtual ~TsaRequest();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
    TsaRequest();
};

namespace TsaVerificationStatus {
  enum Value {
    VERIFIED = 0,
    NOT_VERIFIED,
    UNKNOWN
  };
}

namespace TsaResponseStatus {
  enum Status {
    SUCCESS,
    UNINITIALIZED,
    INVALID_CERT,
    INVALID_KEY,
    INVALID_CA
  };
}

namespace PkiStatus {
  enum Value {
    GRANTED = 0,
    GRANTED_WITH_MODS,
    REJECTION,
    WAITING,
    REVOCATION_WARNING,
    REVOCATION_NOTIFICATION,
    UNKNOWN
  };
}

namespace PkiFailureInfo {
  enum Value {
    BAD_ALGORITHM = 0,
    BAD_REQUEST = 2, /* 10 */
    BAD_DATA_FORMAT = 5, /* 101 */
    TIME_NOT_AVAILABLE = 14, /* 1110 */
    UNACCEPTED_POLICY = 15, /* 1111 */
    UNACCEPTED_EXTENSION = 16, /* 10000 */
    ADDITIONAL_INFO_NOT_AVAILABLE = 17, /* 10001 */
    SYSTEM_FAILURE = 25, /* 11001 */
    NOT_FAILURE = 255
  };
}

/**
 * TsaResponse class
 */
class TsaResponse {
  public:
    /**
     * Constructor
     * @param certificate the certificate of the signer. The certificate extended key usage must be set to "Timestamping" with critical flag, otherwise all operations will be failed with INVALID_CERT status
     * @param privateKey the private key of the signer
     * @param request the TsaRequest data in DER format
     */
    TsaResponse(const Certificate& certificate, const RsaKey& privateKey, std::vector<unsigned char> request);

    /**
     * Sets policyId of the request
     * @param policyId the policy id
     */
    void setPolicyId(const ObjectId& policyId);

    /**
     * Gets the optional policy id of the response.
     * Returns an object id of "0.0.0.0" if there was no policy set before
     * @returns object id of the policy
     */
    const ObjectId& policyId() const;

    /**
     * Gets the representation of the response in DER format
     * @return vector containing DER
     */
    const std::vector<unsigned char> toDer();

    /**
     * Creates a new TsaResponse from DER data
     * @param der DER data
     * @return TsaRequest
     */
    static TsaResponse* fromDer(const std::vector<unsigned char> der, const std::vector<unsigned char> data);

    virtual ~TsaResponse();

    /**
     * Checks whether the response is read only. There are some functions can only applicable
     * in a non-read only response.
     * @returns whether the response is read only
     */
    bool isReadOnly();

    /**
     * Gets the value of PkiStatusInfo
     * @returns The value of PkiStatusInfo
     */
    PkiStatus::Value pkiStatusInfo();

    /**
     * Gets the value of PkiFailureInfo
     * @returns The value of PkiFailureInfo
     */
    PkiFailureInfo::Value pkiFailureInfo();

    /**
     * Adds a digest algorithm to the valid algorithm list. By default, only SHA-1 and SHA-256 is supported.
     * To use accept another digests, you must add them with this function before calling toDer()
     */
    bool addAlgorithm(const ObjectId& algo);

    /**
     * Gets the status of TsaResponse
     * @returns the status of TsaResponse
     */
    TsaResponseStatus::Status status() const;

    /**
     * Sets serial number generation callback function
     * @param func the function which will be called upon response generation
     */
    void setSerialNumberGenerator(std::function<long(void)> cb);

    /**
     * Returns serial number of the response
     * @return serial number
     */
    long serialNumber();

    /**
     * Returns SignedData of the response
     * @return signed data
     */
    SignedData* signedData();

    /**
     * Returns verification status of the token
     * @param certificate The signer certificate
     * @param caFile The CA chain file in PEM format
     * @return verification status
     */
    TsaVerificationStatus::Value verifyToken(const Certificate &certificate, const std::string caFile) const;

    /**
     * Returns verification status of the token
     * @param certificate The signer certificate
     * @return verification status
     */
    TsaVerificationStatus::Value verifyToken(const Certificate &certificate) const;




    /* Internal use */
    long serialCallback();

  private:
    class ImplResponse;
    std::unique_ptr<ImplResponse> impl;
    TsaResponse();
};



} // namespace Erpiko
#endif // _TSA_H_
