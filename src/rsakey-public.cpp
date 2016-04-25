#include "erpiko/rsakey-public.h"
#include "erpiko/utils.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string.h>

namespace Erpiko {

class RsaPublicKey::Impl {
  public:
    RSA* rsa;
    bool success = false;
    BigInt e;
    BigInt n;

    Impl() {
      rsa = RSA_new();
    }

    virtual ~Impl() {
      RSA_free(rsa);
    }

    void fromPem(const std::string pem) {
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      auto ret = PEM_read_bio_RSA_PUBKEY(mem, &rsa, NULL, NULL);
      if (ret) {
        success = true;
        n = BN_bn2dec(rsa->n);
        e = BN_bn2dec(rsa->e);
      }
    }

    void fromDer(const std::vector<unsigned char> der) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      auto ret = d2i_RSA_PUBKEY_bio(mem, &rsa);
      if (ret) {
        success = true;
        n = BN_bn2dec(rsa->n);
        e = BN_bn2dec(rsa->e);
      } else {
        ERR_print_errors_fp (stderr);
      }
    }

    const BigInt& modulus() const {
      return n;
    }

    const BigInt& exponent() const {
      return e;
    }

};

RsaPublicKey::~RsaPublicKey() = default;

RsaPublicKey::RsaPublicKey() : impl{std::make_unique<Impl>()} {
}

RsaPublicKey* RsaPublicKey::fromPem(const std::string pem) {
  RsaPublicKey* rsa = new RsaPublicKey();
  rsa->impl->fromPem(pem);

  if (rsa->impl->success == false) {
    delete(rsa);
    return nullptr;
  }
  return rsa;
}

RsaPublicKey* RsaPublicKey::fromDer(const std::vector<unsigned char> der) {
  RsaPublicKey* rsa = new RsaPublicKey();
  rsa->impl->fromDer(der);

  if (rsa->impl->success == false) {
    delete(rsa);
    return nullptr;
  }
  return rsa;
}

const std::vector<unsigned char> RsaPublicKey::toDer() const {
  std::vector<unsigned char> retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  ret = i2d_RSA_PUBKEY_bio(mem, impl->rsa);

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

const std::string RsaPublicKey::toPem() const {
  std::string retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  ret = PEM_write_bio_RSA_PUBKEY(mem, impl->rsa);

  while (ret) {
    unsigned char buff[1025];
    int ret = BIO_read(mem, buff, 1024);
    if (ret > 0) {
      buff[ret] = 0;
      std::string str = (char*)buff;
      retval += str;
    } else {
      break;
    }
  }
  BIO_free(mem);

  return retval;
}

const BigInt& RsaPublicKey::exponent() const {
  return impl->exponent();
}


const BigInt& RsaPublicKey::modulus() const {
  return impl->modulus();
}


} // namespace Erpiko
