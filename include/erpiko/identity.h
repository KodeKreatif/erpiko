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
     * Creates a new instance of Identity from DER
     * @param der the data in DER format
     */
    static Identity* fromDer(const std::vector<unsigned char> der);

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

    /**
     * Gets a string representation of this identity
     * @return string containing the identity in one line
     */
    const std::string toString(const std::string delimiter = "/") const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _IDENTITY_H_
