#ifndef _SHA1_H
#define _SHA1_H

#include <memory>
#include <vector>
#include "erpiko/digest.h"

namespace Erpiko {

/**
 * Message digest interface
 */
class Sha1 : public Digest {
  public:
    Sha1();
    virtual ~Sha1();

    void update(std::vector<unsigned char> data);
    std::vector<unsigned char> finalize(std::vector<unsigned char> data);
  private:
    class Impl;
    std::unique_ptr<Impl> impl;

};

} // namespace Erpiko
#endif // _SHA1_H
