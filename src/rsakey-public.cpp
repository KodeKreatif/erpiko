#include "erpiko/rsakey-public.h"
#include "erpiko/utils.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <iostream>
#include <string.h>

extern ENGINE* erpikoEngine;

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

    const std::vector<unsigned char> encrypt(const std::vector<unsigned char> data) const {
      std::vector<unsigned char> ret;

      EVP_PKEY* evp = nullptr;
      EVP_PKEY_CTX* ctx = nullptr;
      evp = EVP_PKEY_new();
      if (evp) {
        EVP_PKEY_set1_RSA(evp, rsa);
        ctx = EVP_PKEY_CTX_new(evp, erpikoEngine);
      }

      if (ctx && EVP_PKEY_encrypt_init(ctx)) {
        size_t length = 0;
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_encrypt(ctx, nullptr, &length, data.data(), data.size());

        ret.resize(length);
        unsigned char* buf = ret.data();
        EVP_PKEY_encrypt(ctx, buf, &length, data.data(), data.size());

        EVP_PKEY_CTX_free(ctx);
      }

      if (evp) EVP_PKEY_free(evp);
      return ret;

    }

    bool verify(const std::vector<unsigned char> signature, const std::vector<unsigned char> data, const ObjectId& digest) const {
      bool ret = false;

      EVP_PKEY* evp = nullptr;
      EVP_PKEY_CTX* ctx = nullptr;
      evp = EVP_PKEY_new();

      if (evp) {
        EVP_PKEY_set1_RSA(evp, rsa);
        ctx = EVP_PKEY_CTX_new(evp, erpikoEngine);
      }

      auto obj = OBJ_txt2obj(digest.toString().c_str(), 1);
      auto hashAlgorithmMd = const_cast<EVP_MD*>(EVP_get_digestbyobj(obj));
      ASN1_OBJECT_free(obj);
      if (ctx && EVP_PKEY_verify_init(ctx) && hashAlgorithmMd) {
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_signature_md(ctx, hashAlgorithmMd);
        ret = (EVP_PKEY_verify(ctx, signature.data(), signature.size(), data.data(), data.size()) == 1);

        EVP_PKEY_CTX_free(ctx);
      }

      if (evp) EVP_PKEY_free(evp);
      return ret;

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

const std::vector<unsigned char> RsaPublicKey::encrypt(const std::vector<unsigned char> data) const {
  return impl->encrypt(data);
}

bool RsaPublicKey::verify(const std::vector<unsigned char> signature, const std::vector<unsigned char> data, const ObjectId& digest) const {
  return impl->verify(signature, data, digest);
}


} // namespace Erpiko
