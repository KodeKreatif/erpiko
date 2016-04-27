#ifndef _CONVERTERS_H_
#define _CONVERTERS_H_
#include "erpiko/certificate.h"
#include "erpiko/identity.h"
#include "erpiko/bigint.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <memory>

namespace Erpiko {
namespace Converters {

  inline std::vector<unsigned char> nameToIdentityDer(X509_NAME* n) {
    std::vector<unsigned char> retval;

    auto length = i2d_X509_NAME(n, 0);
    if (length) {
      unsigned char *der = (unsigned char*)malloc(length);
      unsigned char *start = der;
      i2d_X509_NAME(n, &der);
      for (int i = 0; i < length; i ++) {
        retval.push_back(start[i]);
      }
      free(start);
    }
    return retval;
  }

  inline std::string bnToString(BIGNUM *bn) {
    std::string dec;
    dec = BN_bn2dec(bn);
    return dec;
  }

  inline std::vector<unsigned char> rsaToPublicKeyDer(RSA* r) {
    std::vector<unsigned char> v;
    int length = i2d_RSA_PUBKEY(r, 0);
    if (length) {
      unsigned char *der = (unsigned char*)malloc(length);
      // openssl will advances this pointer after populating
      unsigned char *start = der;
      i2d_RSA_PUBKEY(r, &der);
      for (int i = 0; i < length; i ++) {
        v.push_back(start[i]);
      }
      free(start);
    }

    return v;
  }

} // namespace Converters
} // namespace Erpiko
#endif
