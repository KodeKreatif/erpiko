#ifndef _IDENTITY_H_
#define _IDENTITY_H_

#include <string>
#include <memory>

namespace Erpiko {

/**
 * X509 certificate
 */

class Certificate {
  public:
    Certificate();
    virtual ~Certificate();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _IDENTITY_H_
