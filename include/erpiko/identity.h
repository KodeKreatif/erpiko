#ifndef _IDENTITY_H_
#define _IDENTITY_H_

#include <string>
#include <memory>

namespace Erpiko {

/**
 * Collection of X509 Names (RFC4514) which serves as an identity.
 */

class Identity {
  public:
    Identity();
    virtual ~Identity();

    std::string commonName;
    std::string localityName;
    std::string stateOrProvinceName;
    std::string organizationName;
    std::string organizationalUnitName;
    std::string countryName;
    std::string streetAddress;
    std::string domainComponent ;
    std::string userId;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _IDENTITY_H_
