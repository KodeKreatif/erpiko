#ifndef _BIGINT_H_
#define _BIGINT_H_

#include <memory>

namespace Erpiko {

class BigInt {
  public:
    BigInt();
    virtual ~BigInt();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _BIGINT_H_
