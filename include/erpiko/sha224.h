#ifndef _SHA224_H
#define _SHA224_H

#include <memory>
#include <vector>
#include "erpiko/digest.h"

namespace Erpiko {

/**
 * Message digest interface
 */
class Sha224 : public Digest {
  public:
    Sha224();
    virtual ~Sha224();

    void update(std::vector<unsigned char> data);
    std::vector<unsigned char> finalize(std::vector<unsigned char> data);
  private:
    class Impl;
    std::unique_ptr<Impl> impl;

};

} // namespace Erpiko
#endif // _SHA224_H
