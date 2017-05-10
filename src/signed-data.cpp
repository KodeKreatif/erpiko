#include "erpiko/signed-data.h"
#include "erpiko/utils.h"
#include "converters.h"
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <iostream>

namespace Erpiko {

enum SigningMode {
    SIGN,
    DETACHED,
    SMIME
};

class SignedData::Impl {
  public:
    EVP_PKEY *pkey = nullptr;
    X509 *cert;
    PKCS7 *pkcs7 = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());

    std::unique_ptr<RsaKey> privateKey;
    std::vector<std::unique_ptr<Certificate>> ca;
    std::vector<const Certificate*> caPointer;

    int signerInfoIndex = -1;

    bool success = false;
    bool imported = false;
    int nidKey = 0;
    int nidCert = 0;
    SigningMode signingMode;

    Impl() {
      OpenSSL_add_all_algorithms();
    }

    virtual ~Impl() {
      if (pkey && imported == false) {
        EVP_PKEY_free(pkey);
      }
      X509_free(cert);
      BIO_free(bio);
      if (pkcs7) {
        PKCS7_free(pkcs7);
      }
    }

    void setup(const Certificate& certificate, const RsaKey& privateKey) {
      pkey = Converters::rsaKeyToPkey(privateKey);
      cert = Converters::certificateToX509(certificate);
    }

    void fromDer(const std::vector<unsigned char> der, const Certificate& certificate) {
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      pkcs7 = d2i_PKCS7_bio(mem, NULL);
      auto ret = (pkcs7 != nullptr);
      cert = Converters::certificateToX509(certificate);

      if (ret) {
        success = true;
        return;
      }
    }

    void fromPem(const std::string pem, const Certificate& certificate) {
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      pkcs7 = PEM_read_bio_PKCS7(mem, NULL, NULL, NULL);

      auto ret = (pkcs7 != nullptr);

      cert = Converters::certificateToX509(certificate);
      if (ret) {
        success = true;
        return;
      }
    }

    void fromSMime(const std::string smime, const Certificate& certificate) {
      signingMode = SMIME;
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) smime.c_str(), smime.length());
      pkcs7 = SMIME_read_PKCS7(mem, &bio);

      auto ret = (pkcs7 != nullptr);

      cert = Converters::certificateToX509(certificate);
      if (ret) {
        success = true;
        return;
      }
    }

};

SignedData::SignedData() : impl{std::make_unique<Impl>()} {
}

SignedData::SignedData(const Certificate& certificate, const RsaKey& privateKey) : impl{std::make_unique<Impl>()} {
  impl->setup(certificate, privateKey);
}


SignedData* SignedData::fromDer(const std::vector<unsigned char> der, const Certificate& cert) {
  auto p = new SignedData();

  p->impl->fromDer(der, cert);

  if (!p->impl->success) {
    return nullptr;
  }
  return p;
}

SignedData* SignedData::fromPem(const std::string pem, const Certificate& cert) {
  auto p = new SignedData();

  p->impl->fromPem(pem, cert);

  if (!p->impl->success) {
    return nullptr;
  }
  return p;
}



const std::vector<unsigned char> SignedData::toDer() const {
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

SignedData::~SignedData() = default;

bool SignedData::isDetached() const {
  return PKCS7_is_detached(impl->pkcs7);
}

void SignedData::update(const std::vector<unsigned char> data) {
  update(data.data(), data.size());
}

void SignedData::update(const unsigned char* data, const size_t length) {
  BIO_write(impl->bio, data, length);
}

bool SignedData::verify() const {
   STACK_OF(X509) *certs = sk_X509_new_null();
   auto store = X509_STORE_new();
   sk_X509_push(certs, impl->cert);
   auto ret = PKCS7_verify(impl->pkcs7, certs, store, impl->bio, NULL, PKCS7_NOVERIFY) == 1;
   if (ret == 0) {
     ERR_print_errors_fp(stderr);
   }
   sk_X509_free(certs);
   X509_STORE_free(store);
   return ret == 1;
}

void SignedData::signDetached() {
  if (impl->pkcs7) return;

  impl->signingMode = DETACHED;
  impl->pkcs7 = PKCS7_sign(impl->cert, impl->pkey, NULL, impl->bio, PKCS7_DETACHED | PKCS7_NOCERTS | PKCS7_NOSMIMECAP | PKCS7_BINARY);
}

void SignedData::sign() {
  if (impl->pkcs7) return;

  impl->signingMode = SIGN;
  impl->pkcs7 = PKCS7_sign(impl->cert, impl->pkey, NULL, impl->bio,  PKCS7_NOCERTS | PKCS7_NOSMIMECAP | PKCS7_BINARY);
}

void SignedData::signSMime() const {
  if (impl->pkcs7) return;

  impl->signingMode = SMIME;
  impl->pkcs7 = PKCS7_sign(impl->cert, impl->pkey, NULL, impl->bio, PKCS7_STREAM | PKCS7_DETACHED);
}

void SignedData::toSMime(std::function<void(std::string)> onData, std::function<void(void)> onEnd) const {
  if (impl->signingMode != SMIME) {
    onEnd();
    return;
  }

  BIO* out = BIO_new(BIO_s_mem());
  auto r = SMIME_write_PKCS7(out, impl->pkcs7, impl->bio, PKCS7_TEXT | PKCS7_STREAM | PKCS7_DETACHED);

  while (r) {
    unsigned char buff[1025];
    int ret = BIO_read(out, buff, 1024);
    if (ret > 0) {
      buff[ret] = 0;
      std::string str = (char*)buff;
      onData(str);
    } else {
      break;
    }
  }
  BIO_free(out);

  onEnd();
}

const std::string SignedData::toSMime() const {
  std::string retval;

  toSMime([&retval](std::string s) {
        retval += s;
      }, [](){});

  return retval;
}

const std::string SignedData::toPem() const {
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

SignedData* SignedData::fromSMime(const std::string smime, const Certificate& cert) {
  auto p = new SignedData();

  p->impl->fromSMime(smime, cert);

  if (!p->impl->success) {
    return nullptr;
  }
  return p;
}



} // namespace Erpiko
