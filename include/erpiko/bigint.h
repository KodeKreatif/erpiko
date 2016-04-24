#ifndef _BIGINT_H_
#define _BIGINT_H_

#include <memory>

namespace Erpiko {

  /**
   * BigInt is the class of big integer representation.
   */
class BigInt {
  public:
    /**
     * Constructor
     */
    BigInt();

    /**
     * Constructor from long integer
     * @param value to be initialized
     */
    BigInt(unsigned long value);

    /**
     * Creates a new BigInt and initialized with the value specified in the string
     * @param string string containing the value. If it is prefixed with 0x then it is considered as hex string
     * @return the new BigInt with the value set
     */
    static BigInt* fromString(const std::string string);
    virtual ~BigInt();

    /**
     * Creates hex string representation of the BigInt
     * @return string containing hex string
     */
    const std::string toHexString() const;

    /**
     * Operator ==
     **/
    bool operator== (const BigInt& other);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _BIGINT_H_
