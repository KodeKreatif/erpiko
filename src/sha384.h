#ifndef _SHA384_H
#define _SHA384_H

#include <memory>
#include <vector>
#include "erpiko/digest.h"

namespace Erpiko {

/**
 * Message digest interface
 */
class Sha384 : public Digest {
  public:
    Sha384();
    virtual ~Sha384();

    void update(std::vector<unsigned char> data);
    std::vector<unsigned char> finalize(std::vector<unsigned char> data);
  private:
    class Impl;
    std::unique_ptr<Impl> impl;

};

} // namespace Erpiko
#endif // _SHA384_H
