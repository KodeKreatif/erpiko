#ifndef _SHA512_H
#define _SHA512_H

#include <memory>
#include <vector>
#include "erpiko/digest.h"

namespace Erpiko {

/**
 * Message digest interface
 */
class Sha512 : public Digest {
  public:
    Sha512();
    virtual ~Sha512();

    void update(std::vector<unsigned char> data);
    std::vector<unsigned char> finalize(std::vector<unsigned char> data);
  private:
    class Impl;
    std::unique_ptr<Impl> impl;

};

} // namespace Erpiko
#endif // _SHA512_H
