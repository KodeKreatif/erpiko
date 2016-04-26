#ifndef _IDENTITY_H_
#define _IDENTITY_H_

#include <string>
#include <memory>
#include <vector>

namespace Erpiko {

/**
 * Collection of X509 Names (RFC4514) which serves as an identity.
 */

class Identity {
  public:
    Identity();
    virtual ~Identity();

    /**
     * Operator ==
     **/
    bool operator== (const Identity& other) const;

    /**
     * Gets DER representation of the Identity
     * @return vector containing the DER data
     */
    const std::vector<unsigned char> toDer() const;

    /**
     * Gets a value under the specified key name
     * @param name the key name
     * @return string value of the key
     */
    const std::string get(const std::string name) const;

    /**
     * Sets the value of the key as specified.
     * @param name the key name
     * @param value the value of the key
     */
    void set(const std::string name, const std::string value);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _IDENTITY_H_
