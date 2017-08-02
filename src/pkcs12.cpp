#include "erpiko/pkcs12.h"
#include "converters.h"
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <iostream>

namespace Erpiko {
class Pkcs12::Impl {
  public:
    PKCS12* p12;
    EVP_PKEY *pkey;
    X509 *cert;
    PKCS12_SAFEBAG *dataBag = nullptr;

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
        if (caStack != nullptr) {
          sk_X509_free(caStack);
        }
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

      if (dataBag != nullptr) {
        STACK_OF(PKCS7)* p7s = PKCS12_unpack_authsafes(p12);
        STACK_OF(PKCS12_SAFEBAG)* bags = sk_PKCS12_SAFEBAG_new_null();
        sk_PKCS12_SAFEBAG_push(bags, dataBag);
        PKCS12_add_safe(&p7s, bags, 0, 0, (char*) passphrase.c_str());
        PKCS12_pack_authsafes(p12, p7s);
        PKCS12_set_mac(p12, passphrase.c_str(), -1, NULL, 0, 0, NULL);
      }
    }

    void addData(const std::vector<unsigned char> data, const ObjectId& oid) {
      auto octetString = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(octetString, data.data(), data.size());
      auto asn1Type = ASN1_TYPE_new();
      ASN1_TYPE_set(asn1Type, octetString->type, (char *)octetString);

      auto bag = PKCS12_BAGS_new();
      bag->type = OBJ_txt2obj(oid.toString().c_str(), 0);
      bag->value.other = asn1Type;

      dataBag = PKCS12_SAFEBAG_new();
      dataBag->value.bag = bag;
      dataBag->type = OBJ_nid2obj(NID_secretBag);
    }

    const std::vector<unsigned char> getData(const ObjectId& oid) {
      std::vector<unsigned char> retval;
      STACK_OF(PKCS7)* p7s = PKCS12_unpack_authsafes(p12);

      while (true) {
        PKCS7* p7 = sk_PKCS7_pop(p7s);
        if (p7 == nullptr) break;

        STACK_OF(PKCS12_SAFEBAG)* bags = nullptr;
        if (PKCS7_type_is_encrypted(p7)) {
          bags = PKCS12_unpack_p7encdata(p7, passphrase.c_str(), passphrase.length());
        } else {
          bags = PKCS12_unpack_p7data(p7);
        }
        while (true) {
          auto bag = sk_PKCS12_SAFEBAG_pop(bags);
          if (bag == nullptr) break;

          auto nid = OBJ_obj2nid(bag->type);
          if (nid == NID_secretBag) {
            auto p12bag = bag->value.bag;
            auto value = p12bag->value.other;
            auto contentId = OBJ_txt2obj(oid.toString().c_str(), 0);
            if (OBJ_cmp(p12bag->type, contentId) == 0) {
              auto length = ASN1_STRING_length(value->value.octet_string);
              retval.resize(length);

              ASN1_TYPE_get_octetstring(value, &retval[0], length);
              PKCS12_SAFEBAG_free(bag);
              sk_PKCS12_SAFEBAG_free(bags);
              PKCS7_free(p7);
              sk_PKCS7_free(p7s);

              return retval;
            }
          }
          PKCS12_SAFEBAG_free(bag);
        }
        sk_PKCS12_SAFEBAG_free(bags);
        PKCS7_free(p7);
      }
      sk_PKCS7_free(p7s);
      return retval;
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
  if (impl->pkey) {
    EVP_PKEY_free(impl->pkey);
  }
  impl->pkey = Converters::rsaKeyToPkey(key);
  impl->privateKey.reset(const_cast<RsaKey*>(&key));
}

const Certificate& Pkcs12::certificate() const {
  return *impl->certificate.get();
}

void Pkcs12::certificate(const Certificate& cert) {
  auto der = cert.toDer();
  BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
  d2i_X509_bio(mem, &impl->cert);
  impl->certificate.reset(Certificate::fromDer(der));
  BIO_free(mem);
}

const std::vector<const Certificate*>& Pkcs12::certificateChain() const {
  return impl->caPointer;
}

void Pkcs12::data(const std::vector<unsigned char> data, const ObjectId& oid) {
  impl->addData(data, oid);
}

const std::vector<unsigned char> Pkcs12::data(const ObjectId& oid) const {
  return impl->getData(oid);
}


} // namespace Erpiko
