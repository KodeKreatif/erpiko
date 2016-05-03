#ifndef _CONVERTERS_H_
#define _CONVERTERS_H_
#include "erpiko/certificate.h"
#include "erpiko/identity.h"
#include "erpiko/bigint.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include <memory>
#include <iostream>

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

  inline const std::vector<unsigned char> rsaKeyToDer(EVP_PKEY *pkey, const std::string passphrase) {
    std::vector<unsigned char> retval;
    int ret;
    BIO* mem = BIO_new(BIO_s_mem());

    if (passphrase == "") {
      ret = i2d_PKCS8PrivateKey_bio(mem, pkey, NULL, NULL, 0, 0, NULL);
    } else {
      ret = i2d_PKCS8PrivateKey_bio(mem, pkey, EVP_aes_256_cbc(), const_cast<char*>(passphrase.c_str()), passphrase.length(), 0, NULL);
    }

    while (ret) {
      unsigned char buff[1024];
      int ret = BIO_read(mem, buff, 1024);
      if (ret > 0) {
        for (int i = 0; i < ret; i ++) {
          retval.push_back(buff[i]);
        }
      } else {
        break;
      }
    }
    BIO_free(mem);

    return retval;
  }

  inline std::vector<unsigned char> certificateToDer(X509* r) {
    std::vector<unsigned char> v;
    int length = i2d_X509(r, 0);
    if (length) {
      unsigned char *der = (unsigned char*)malloc(length);
      // openssl will advances this pointer after populating
      unsigned char *start = der;
      i2d_X509(r, &der);
      for (int i = 0; i < length; i ++) {
        v.push_back(start[i]);
      }
      free(start);
    }

    return v;
  }

  inline std::vector<unsigned char> pkcs12ToDer(PKCS12* r) {
    std::vector<unsigned char> retval;
    int ret;
    BIO* mem = BIO_new(BIO_s_mem());

    ret = i2d_PKCS12_bio(mem, r);
    std::cout << ret << "\n";

        ERR_print_errors_fp (stderr);

    while (ret) {
      unsigned char buff[1024];
      int ret = BIO_read(mem, buff, 1024);
      if (ret > 0) {
        for (int i = 0; i < ret; i ++) {
          retval.push_back(buff[i]);
        }
      } else {
        break;
      }
    }
    BIO_free(mem);

    return retval;
  }




} // namespace Converters
} // namespace Erpiko
#endif
