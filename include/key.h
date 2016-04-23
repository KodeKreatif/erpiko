#ifndef _KEY_H_
#define _KEY_H_

#include <memory>

namespace Erpiko {

class RsaKey {
  public:
    /**
     * Creates a new instance of RSA key
     */
    RsaKey();
    virtual ~RsaKey();

    static RsaKey* create(const unsigned int bits);

    /**
     * Gets the number of bits of this key
     */
    unsigned int bits() const;


  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _KEY_H_
