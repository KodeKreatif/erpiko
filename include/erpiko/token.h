#ifndef _TOKEN_H_
#define _TOKEN_H_
#include <string>
#include <memory>
#include <vector>


namespace Erpiko {

class Certificate;

namespace CardStatus {
enum Value {
    PRESENT,
    NOT_PRESENT,
};
}

namespace TokenOpResult {
  enum Value {
    SUCCESS,
    GENERIC_ERROR,
    TOO_LARGE,
    READ_ONLY
  };
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
     * Sets key id and label to be recorded in the device
     * @param id the id of the key
     * @param label the label of the key
     */
    virtual void setKeyId(const unsigned int id, const std::string& label) = 0;

    /**
     * Puts an arbitrary data into token
     * @param applicationName application name
     * @param the label of the data
     * @param data
     * @return Token operation result
     */
    virtual TokenOpResult::Value putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data) = 0;

    /**
     * Gets an arbitrary data out of the token
     * @param applicationName application name
     * @param the label of the data
     * @return the data if found, otherwise it will return an empty vector
     */
    virtual std::vector<unsigned char> getData(const std::string& applicationName, std::string& label) = 0;

    /**
     * Gets list of certificate(s) from smartcard
     * @return a vector of Erpiko::Certificate*
     */
    virtual std::vector<Certificate*> getCertificates() = 0;

    /**
     * Returns internal engine handle
     * @return internal handle
     */
    virtual void* engine() const = 0;

};
} // namespace Erpiko
#endif // _TOKEN_H_
