#include "erpiko/enveloped-data.h"
#include "erpiko/utils.h"
#include "converters.h"
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <iostream>

namespace Erpiko {
class EnvelopedData::Impl {
  public:
    X509 *cert = nullptr;

    std::unique_ptr<ObjectId> oid;
    PKCS7 *pkcs7 = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());

    bool success = false;
    bool imported = false;

    Impl() {
      OpenSSL_add_all_algorithms();
    }

    virtual ~Impl() {
      X509_free(cert);

      BIO_free(bio);
      if (pkcs7) {
        PKCS7_free(pkcs7);
      }
    }


    void fromDer(const std::vector<unsigned char> der) {
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      pkcs7 = d2i_PKCS7_bio(mem, NULL);
      auto ret = (pkcs7 != nullptr);

      if (ret) {
        success = true;
        return;
      }
    }

    void fromPem(const std::string pem) {
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      pkcs7 = PEM_read_bio_PKCS7(mem, NULL, NULL, NULL);

      auto ret = (pkcs7 != nullptr);

      if (ret) {
        success = true;
        return;
      }
    }

    const EVP_CIPHER* getCipher() {
      auto obj = OBJ_txt2obj(oid->toString().c_str(), 0);
      return EVP_get_cipherbyobj(obj);
    }

    void encrypt(const std::vector<unsigned char> data) {
      if (pkcs7) {
        PKCS7_free(pkcs7);
        pkcs7 = nullptr;
      }
      STACK_OF(X509)* certs = sk_X509_new_null();
      sk_X509_push(certs, cert);
      BIO_write(bio, data.data(), data.size());

      auto cipher = getCipher();
      if (cipher != nullptr) {
        pkcs7 = PKCS7_encrypt(certs, bio, cipher, PKCS7_BINARY);
      }
    }

    const std::vector<unsigned char> decrypt(const Certificate& certificate, const RsaKey& privateKey) {
      EVP_PKEY *pkey = nullptr;
      pkey = Converters::rsaKeyToPkey(privateKey);
      if (cert) {
        X509_free(cert);
        cert = nullptr;
      }
      cert = Converters::certificateToX509(certificate);
      auto ret = PKCS7_decrypt(pkcs7, pkey, cert, bio, 0);

      std::vector<unsigned char> retval;
      while (ret) {
        unsigned char buff[1024];
        int ret = BIO_read(bio, buff, 1024);
        if (ret > 0) {
          for (int i = 0; i < ret; i ++) {
            retval.push_back(buff[i]);
          }
        } else {
          break;
        }
      }

      EVP_PKEY_free(pkey);
      return retval;
    }
};

EnvelopedData::EnvelopedData() : impl{std::make_unique<Impl>()} {
}

EnvelopedData::EnvelopedData(const Certificate& certificate, const ObjectId& oid) : impl{std::make_unique<Impl>()} {
  impl->oid.reset(new ObjectId(oid.toString()));
  impl->cert = Converters::certificateToX509(certificate);
}

EnvelopedData* EnvelopedData::fromDer(const std::vector<unsigned char> der) {
  auto p = new EnvelopedData();

  p->impl->fromDer(der);

  if (!p->impl->success) {
    return nullptr;
  }
  return p;
}

EnvelopedData* EnvelopedData::fromPem(const std::string pem) {
  auto p = new EnvelopedData();

  p->impl->fromPem(pem);

  if (!p->impl->success) {
    return nullptr;
  }
  return p;
}



const std::vector<unsigned char> EnvelopedData::toDer() const {
  std::vector<unsigned char> retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  ret = i2d_PKCS7_bio_stream(mem, impl->pkcs7, NULL, 0);

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

EnvelopedData::~EnvelopedData() = default;

void EnvelopedData::encrypt(const std::vector<unsigned char> data) {
  impl->encrypt(data);
}


const std::string EnvelopedData::toPem() const {
  std::string retval;
  int ret;
  BIO* mem = BIO_new(BIO_s_mem());

  ret = PEM_write_bio_PKCS7_stream(mem, impl->pkcs7, NULL, 0);

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


const std::vector<unsigned char> EnvelopedData::decrypt(const Certificate& certificate, const RsaKey& privateKey) const {
  return impl->decrypt(certificate, privateKey);
}

} // namespace Erpiko
