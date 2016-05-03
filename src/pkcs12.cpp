#include "erpiko/pkcs12.h"
#include "converters.h"
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <iostream>

namespace Erpiko {
class Pkcs12::Impl {
  public:
    PKCS12* p12;
    EVP_PKEY *pkey;
    X509 *cert;

    std::unique_ptr<RsaKey> privateKey;
    std::unique_ptr<Certificate> certificate;
    std::vector<std::unique_ptr<Certificate>> ca;
    std::vector<const Certificate*> caPointer;

    bool success = false;
    bool imported = false;
    int nidKey = 0;
    int nidCert = 0;
    std::string passphrase;
    std::string label;

    Impl() {
      OpenSSL_add_all_algorithms();
      p12 = PKCS12_new();
      pkey = EVP_PKEY_new();
      cert = X509_new();
    }

    virtual ~Impl() {
      passphrase = "";
      EVP_PKEY_free(pkey);
      X509_free(cert);
      PKCS12_free(p12);
    }

    void fromDer(const std::vector<unsigned char> der, const std::string passphrase) {
      imported = true;
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      d2i_PKCS12_bio(mem, &p12);
      STACK_OF(X509) *caStack = sk_X509_new_null();

      auto ret = PKCS12_parse(p12, passphrase.c_str(), &pkey, &cert, &caStack);
      BIO_free(mem);
      if (ret == 0) {
        ERR_print_errors_fp (stderr);
        return;
      }
      auto keyDer = Converters::rsaKeyToDer(pkey, "");
      privateKey.reset(RsaKey::fromDer(keyDer));

      auto certDer = Converters::certificateToDer(cert);
      certificate.reset(Certificate::fromDer(certDer));

      if (caStack != nullptr) {
        for (int i = 0; i < sk_X509_num(caStack); i ++) {
          auto certItem = sk_X509_value(caStack, i);
          auto certItemDer = Converters::certificateToDer(certItem);
          std::unique_ptr<Certificate> c;
          c.reset(Certificate::fromDer(certItemDer));
          caPointer.push_back(c.get());
          ca.push_back(std::move(c));
        }
        sk_X509_free(caStack);
      }

      success = true;
    }

    void buildP12() {
      if (p12) {
        PKCS12_free(p12);
        p12 = nullptr;
      }
      p12 = PKCS12_create((char*) passphrase.c_str(),
          (char*) label.c_str(), pkey, cert, NULL, nidKey, nidCert, 0, 0, 0);
    }

};

Pkcs12* Pkcs12::fromDer(const std::vector<unsigned char> der, const std::string passphrase) {
  auto p = new Pkcs12("", passphrase);

  p->impl->fromDer(der, passphrase);

  if (!p->impl->success) {
    return nullptr;
  }

  return p;
}

Pkcs12::Pkcs12(const std::string label, const std::string passphrase) : impl{std::make_unique<Impl>()}{
  impl->label = label;
  impl->passphrase = passphrase;
}

const std::vector<unsigned char> Pkcs12::toDer() const {
  if (impl->imported == false) {
    impl->buildP12();
  }
  return Converters::pkcs12ToDer(impl->p12);
}

Pkcs12::~Pkcs12() = default;

const RsaKey& Pkcs12::privateKey() const {
  return *impl->privateKey.get();
}

void Pkcs12::privateKey(const RsaKey& key) {
  auto der = key.toDer();
  BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
  PKCS8_PRIV_KEY_INFO *p8inf;
  p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem, NULL);

  if (p8inf) {
    if (impl->pkey) {
      EVP_PKEY_free(impl->pkey);
    }
    impl->pkey = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
  }
}

const Certificate& Pkcs12::certificate() const {
  return *impl->certificate.get();
}

void Pkcs12::certificate(const Certificate& cert) {
  auto der = cert.toDer();
  BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
  d2i_X509_bio(mem, &impl->cert);
}

const std::vector<const Certificate*>& Pkcs12::certificateChain() const {
  return impl->caPointer;
}

} // namespace Erpiko
