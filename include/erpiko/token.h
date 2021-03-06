#ifndef _TOKEN_H_
#define _TOKEN_H_
#include "erpiko/rsakey.h"
#include "erpiko/certificate.h"
#include <string>
#include <memory>
#include <vector>

namespace Erpiko {

class Certificate;

namespace CardStatus {
enum Value {
    PRESENT,
    NOT_PRESENT,
    NOT_SUPPORTED,
};
}

namespace TokenOpResult {
  enum Value {
    SUCCESS,
    GENERIC_ERROR,
    TOO_LARGE,
    READ_ONLY,
    ALREADY_EXIST,
  };
};

struct SlotInfo {
  std::string description;
  std::string manufacturerID;
  unsigned long flags;
  unsigned long slotId;
};

struct TokenInfo {
  std::string label;
  std::string manufacturer;
  std::string model;
  std::string serialNumber;
  std::string flags;
  unsigned long tokenFlags;
  unsigned long slotsFlags;
  int maxSessionCount;
  int sessionCount;
  int maxRwSessionCount;
  int rwSessionCount;
  int maxPinlen;
  int minPinlen;
  int totalPublicMemory;
  int freePublicMemory;
  int totalPrivateMemory;
  int freePrivateMemory;
  std::string hardwareVersion;
  std::string firmwareVersion;
  unsigned long int slotId;
};

/**
 * Hardware token interface
 */
class Token {
  public:
    /**
     * Loads a dynamic library provided by the token manufacturer
     * @param path path to the dynamic library
     */
    virtual bool load(const std::string path) = 0;

    /**
     * Unloads the loaded dynamic library
     */
    virtual void unload() = 0;

    /**
     * Checks whether the token is valid or not
     * @return the value
     */
    virtual bool isValid() = 0;
    /**
     * Wait for slot event on reader device. This is a blocking function until the event occured.
     * @param slot the slot, the slot ID will be assigned here if the return value is true
     * @return returned if the an event has been occured
     */
    virtual CardStatus::Value waitForCardStatus(int &slot) const = 0;
    /**
     * Open the session of specific slot
     * @return whether the smartcard is present or not in the slot
     */
    /**
     * Performs login on the device
     * @param slot the slot
     * @param pin the pin used for login
     * @return whether the login was successfully performed
     */
    virtual bool login(const unsigned long slot, const std::string& pin) const = 0;

    /**
     * Performs logout on the device
     * @return whether the logout was successfully performed
     */
    virtual bool logout() const = 0;

    /**
     * Open session for the device
     * @param slot the slot
     * @return whether the session was successfully opened
     */
    virtual bool openSession(const unsigned long slot) const = 0;

    /**
     * Close the session on the device
     * @return whether the session was successfully closed
     */
    virtual bool closeSession() const = 0;

    /**
     * Sets key id and label to be recorded or used in the device
     * @param id the id of the key
     * @param label the label of the key
     */
    virtual void setKeyId(const unsigned int id, const std::string& label) = 0;

    /**
     * Sets key id to be recorded or used in the device
     * @param id the id of the key
     */
    virtual void setKeyId(const unsigned int id) = 0;

    /**
     * Sets key label to be recorded or used in the device
     * @param id the id of the key
     * @param label the label of the key
     */
    virtual void setKeyLabel(const std::string& label) = 0;

    /**
     * Unsets both keyId and label
     */
    virtual void unsetKey() = 0;

    /**
     * Puts an arbitrary data into token
     * @param applicationName application name
     * @param the label of the data
     * @param data
     * @return Token operation result
     */
    virtual TokenOpResult::Value putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data) = 0;

    /**
     * Puts an arbitrary data into token with the label as identifier. This will check first
     * the existence of the data with the mentioned label. If there is a value with the label,
     * it will be overriden with the new value.
     * @param applicationName application name
     * @param the label of the data
     * @param data
     * @return Token operation result
     */
    virtual TokenOpResult::Value putUniqueData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data) = 0;

    /**
     * Gets an arbitrary data out of the token. This will get the first occurence of the data
     * identified with the specified label.
     * @param applicationName application name
     * @param the label of the data
     * @return the data if found, otherwise it will return an empty vector
     */
    virtual std::vector<unsigned char> getData(const std::string& applicationName, std::string& label) = 0;

    /**
     * Gets all data out of the token as identified with a label
     * @param applicationName application name
     * @param the label of the data
     * @return the data if found, otherwise it will return an empty vector
     */
    virtual std::vector<std::vector<unsigned char>> getAllData(const std::string& applicationName, std::string& label) = 0;

    /**
     * Removes arbitrary data out of the token
     * @param applicationName application name
     * @param the label of the data
     * @return true if data is removed
     */
    virtual bool removeData(const std::string& applicationName, const std::string& label) = 0;

    /**
     * Gets list of certificate(s) from smartcard
     * @param withPrivateKey whether the certificates should be accompanied by a private key
     * @return a vector of Erpiko::Certificate*
     */
    virtual std::vector<Certificate*> getCertificates(bool withPrivateKey = false) = 0;

    /**
     * Puts a certificate into token
     * @param cert the certificate in Certificate format
     * @return Token operation result
     */
    virtual TokenOpResult::Value putCertificate(const Certificate& cert) = 0;

    /**
     * Removes a certificate from the token
     * @param cert the certificate in Certificate format
     * @return Token operation result
     */
    virtual bool removeCertificate(const Certificate& cert) = 0;

    /**
     * Puts a private key into the token
     * @param data the private key
     * @param labelStr the label on the token
     * @return Token operation result
     */
    virtual TokenOpResult::Value putPrivateKey(const RsaKey& data, const std::string& labelStr) = 0;

    /**
     * Gets a private key from the token
     * @param publicKey of the private key
     * @return a RsaKey with onDevice property true
     */
    virtual RsaKey* getPrivateKey(const RsaPublicKey& publicKey) = 0;

    /**
     * Removes a private key from the token
     * @param labelStr the label on the token
     * @return true if data is removed
     */
    virtual bool removePrivateKey(const std::string& labelStr) = 0;

    /**
     * Get the list of token information if it presents on slot(s)
     * @return slots return the slots that has token present, each described with TokenInfo object
     */
    virtual std::vector<TokenInfo> getAllTokensInfo() = 0;

    /**
    * Get the list of slot information
    * @param isTokenPresentOnly sets true to retrieve all slots if token is available, sets false to retrieve all slots even if tokens are unavailable
    * @return slots return the slots that has token present, each described with SlotInfo object
    */
    virtual std::vector<SlotInfo> getAllSlotsInfo(bool isTokenPresentOnly = false) = 0;

    /**
     * Returns internal engine handle
     * @return internal handle
     */
    virtual void* engine() const = 0;

    /**
     * Retrieves card information in the token
     * @param token
     * @return card is present or not 
    */
    virtual CardStatus::Value getCardStatus(TokenInfo token) = 0;

    /**
     * Retrieves card's current session, the session will be available after OpenSession
     * @return session
    */
    virtual unsigned long int getCardSession() = 0;
    
    /**
     * Checks whether token/smart card is present on given slotInfo
     * @param slotInfo, slot structure retrieved from getAllSlotsInfo()
     * @return true if token present, false if otherwise
    */
    virtual bool isTokenPresent(const SlotInfo& slotInfo) = 0;

    /**
    * Checks whether given slotInfo is a hardware slot
    * @param slotInfo, slot structure retrieved from getAllSlotsInfo()
    * @return true if it is a hardware slot, false if otherwise
    */
    virtual bool isHardwareSlot(const SlotInfo& slotInfo) = 0;

    /**
    * Checks whether given slotInfo
    * @param slotInfo, slot structure retrieved from getAllSlotsInfo()
    * @return true if slot removable, false if otherwise
    */
    virtual bool isRemovableDevice(const SlotInfo& slotInfo) = 0;

};
} // namespace Erpiko
#endif // _TOKEN_H_
