#include "erpiko/rsakey.h"
#include "erpiko/rsakey-public.h"
#include "erpiko/utils.h"
#include "converters.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <string.h>

namespace Erpiko {

class RsaKey::Impl {
  public:
    unsigned int bits = 0;
    int ret;
    RSA* rsa;
    EVP_PKEY* evp;
    bool evpPopulated = false;
    std::unique_ptr<RsaPublicKey> publicKey;

    Impl() {
      rsa = RSA_new();
      evp = EVP_PKEY_new();
      OpenSSL_add_all_algorithms();
    }

    virtual ~Impl() {
      RSA_free(rsa);
      EVP_PKEY_free(evp);
    }

    void resetPublicKey() {
      RSA *r = rsa;
      if (evpPopulated) {
        r = evp->pkey.rsa;
      }
      auto der = Converters::rsaToPublicKeyDer(r);
      publicKey.reset(RsaPublicKey::fromDer(der));
    }

    void createKey(const unsigned int bits) {
      unsigned long e = RSA_F4;
      BIGNUM* bne = BN_new();
      ret = BN_set_word(bne, e);
      if (ret != 1) {
        return;
      }
      ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
      if (ret != 1) {
        BN_free(bne);
        return;
      }
      BN_free(bne);
      this->bits = bits;
      resetPublicKey();
    }

    void fromPem(const std::string pem, const std::string passphrase) {
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      EVP_PKEY *ret;
      if (passphrase == "") {
        ret = PEM_read_bio_PrivateKey(mem, &evp, NULL, NULL);
      } else {
        ret = PEM_read_bio_PrivateKey(mem, &evp, NULL, (void*) passphrase.c_str());
      }
      if (ret) {
        evpPopulated = true;
        bits = BN_num_bits(evp->pkey.rsa->n);
        resetPublicKey();
      }
    }

    void fromDer(const std::vector<unsigned char> der, const std::string passphrase) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      if (passphrase == "") {
        PKCS8_PRIV_KEY_INFO *p8inf;
        p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem, NULL);

        if (p8inf) {
          evp = EVP_PKCS82PKEY(p8inf);
          PKCS8_PRIV_KEY_INFO_free(p8inf);

          evpPopulated = true;
          bits = BN_num_bits(evp->pkey.rsa->n);
        }
      } else {
        EVP_PKEY *ret;
        ret = d2i_PKCS8PrivateKey_bio(mem, &evp, NULL, (void*) passphrase.c_str());
        if (ret) {
          evpPopulated = true;
          bits = BN_num_bits(evp->pkey.rsa->n);
          resetPublicKey();
        }
      }
    }
};

RsaKey::~RsaKey() = default;

RsaKey::RsaKey() : impl{std::make_unique<Impl>()} {
}

RsaKey* RsaKey::create(const unsigned int bits) {
  RsaKey* rsa = new RsaKey();

  rsa->impl->createKey(bits);
  if (bits == rsa->impl->bits) {
    return rsa;
  } else {
    return nullptr;
  }
}

RsaKey* RsaKey::fromPem(const std::string pem, const std::string passphrase) {
  RsaKey* rsa = new RsaKey();
  rsa->impl->fromPem(pem, passphrase);

  if (rsa->impl->evpPopulated == false) {
    return nullptr;
  }
  return rsa;
}

RsaKey* RsaKey::fromDer(const std::vector<unsigned char> der, const std::string passphrase) {
  RsaKey* rsa = new RsaKey();
  rsa->impl->fromDer(der, passphrase);

  if (rsa->impl->evpPopulated == false) {
    return nullptr;
  }
  return rsa;
}



unsigned int RsaKey::bits() const {
  return impl->bits;
}

const std::string RsaKey::toPem(const std::string passphrase) const {
  std::string retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  if (impl->evpPopulated == false) {
    EVP_PKEY_set1_RSA(impl->evp, impl->rsa);
  }
  if (passphrase == "") {
    ret = PEM_write_bio_PKCS8PrivateKey(mem, impl->evp, NULL, NULL, 0, 0, NULL);
  } else {
    ret = PEM_write_bio_PKCS8PrivateKey(mem, impl->evp, EVP_aes_256_cbc(), const_cast<char*>(passphrase.c_str()), passphrase.length(), 0, NULL);
  }

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

const std::vector<unsigned char> RsaKey::toDer(const std::string passphrase) const {
  std::vector<unsigned char> retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  if (impl->evpPopulated == false) {
    EVP_PKEY_set1_RSA(impl->evp, impl->rsa);
  }
  if (passphrase == "") {
     ret = i2d_PKCS8PrivateKey_bio(mem, impl->evp, NULL, NULL, 0, 0, NULL);
  } else {
     ret = i2d_PKCS8PrivateKey_bio(mem, impl->evp, EVP_aes_256_cbc(), const_cast<char*>(passphrase.c_str()), passphrase.length(), 0, NULL);
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

const RsaPublicKey& RsaKey::publicKey() const {
  return *impl->publicKey.get();
}

} // namespace Erpiko
