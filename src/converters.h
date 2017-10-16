#ifndef _CONVERTERS_H_
#define _CONVERTERS_H_
#include "erpiko/certificate.h"
#include "erpiko/identity.h"
#include "erpiko/bigint.h"
#include "erpiko/rsakey.h"
#include "erpiko/sim.h"
#include "erpiko/utils.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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

  inline const std::vector<unsigned char> rsaKeyToDer(EVP_PKEY *pkey, const std::string passphrase, bool isPublic = false) {
    std::vector<unsigned char> retval;
    int ret;
    BIO* mem = BIO_new(BIO_s_mem());

    if (isPublic) {
      auto rsa = EVP_PKEY_get1_RSA(pkey);
      ret = i2d_RSA_PUBKEY_bio(mem, rsa);
    } else {
      if (passphrase == "") {
        ret = i2d_PKCS8PrivateKey_bio(mem, pkey, NULL, NULL, 0, 0, NULL);
      } else {
        ret = i2d_PKCS8PrivateKey_bio(mem, pkey, EVP_aes_256_cbc(), const_cast<char*>(passphrase.c_str()), passphrase.length(), 0, NULL);
      }
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

  inline std::string certificateRequestToPem(X509_REQ* r) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, r);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem->data, mem->length);
    BIO_free(bio);

    return pem;
  }

  inline std::vector<unsigned char> certificateRequestToDer(X509_REQ* r) {
    std::vector<unsigned char> retval;
    int ret;
    BIO* mem = BIO_new(BIO_s_mem());

    ret = i2d_X509_REQ_bio(mem, r);

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


  inline std::string certificateToPem(X509* r) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, r);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem->data, mem->length);
    BIO_free(bio);

    return pem;
  }

  inline std::vector<unsigned char> pkcs12ToDer(PKCS12* r) {
    std::vector<unsigned char> retval;
    int ret;
    BIO* mem = BIO_new(BIO_s_mem());

    ret = i2d_PKCS12_bio(mem, r);

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

  inline EVP_PKEY* rsaKeyToPkey(const RsaKey& key) {
    EVP_PKEY* pkey = nullptr;
    auto der = key.toDer();
    BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
    PKCS8_PRIV_KEY_INFO *p8inf;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem, NULL);

    if (p8inf) {
      pkey = EVP_PKCS82PKEY(p8inf);
      PKCS8_PRIV_KEY_INFO_free(p8inf);
    }
    return pkey;
  }

  inline X509_NAME* identityToName(const Identity& identity) {
    auto der = identity.toDer();
    const unsigned char* raw = der.data();
    auto name = d2i_X509_NAME(0, &raw, der.size());
    return name;
  }

  inline X509* certificateToX509(const Certificate& cert) {
    auto der = cert.toDer();
    const unsigned char* raw = der.data();
    auto x509 = d2i_X509(0, &raw, der.size());
    return x509;
  }

  inline GENERAL_NAME* simToGeneralName(const Sim& sim) {
    auto simValue = sim.toDer();
    ASN1_TYPE* otherName = ASN1_TYPE_new();
    ASN1_TYPE_set_octetstring(otherName, simValue.data(), simValue.size());

    GENERAL_NAME* retval = GENERAL_NAME_new();
    GENERAL_NAME_set0_othername(retval, OBJ_txt2obj("1.3.6.1.5.5.7.8.6", 1), otherName);

    return retval;
  }

} // namespace Converters
} // namespace Erpiko
#endif
