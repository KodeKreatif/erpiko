#ifndef _TOKEN_H_
#define _TOKEN_H_

#include <memory>
namespace Erpiko {

/**
 * Hardware token interface
 */
class Token {
  public:
    Token();
    virtual ~Token();
    /**
     * Loads a dynamic library provided by the token manufacturer
     * @param path path to the dynamic library
     */
    bool load(const std::string path);

    /**
     * Checks whether the token is valid or not
     * @return the value
     */
    bool isValid();
    /**
     * Performs login on the device
     * @param slot the slot
     * @param pin the pin used for login
     * @return whether the login was successfully performed
     */
    bool login(const unsigned long slot, const std::string& pin) const;

    /**
     * Performs logout on the device
     * @return whether the logout was successfully performed
     */
    bool logout() const;

    /**
     * Sets key id and label to be recorded in the device
     * @param id the id of the key
     * @param label the label of the key
     */
    void setKeyId(const unsigned int id, const std::string& label);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};
} // namespace Erpiko
#endif // _TOKEN_H_
