#include "erpiko/utils.h"
#include "erpiko/certificate.h"
#include "erpiko/certificate-extension.h"
#include "converters.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <string.h>
#include <iostream>
#include <algorithm>

namespace Erpiko {

class Certificate::Impl {
  public:
    X509* x509;
    bool success = false;
    std::unique_ptr<Identity> subjectIdentity;
    std::unique_ptr<Identity> issuerIdentity;
    std::unique_ptr<RsaPublicKey> publicKey;
    std::vector<std::unique_ptr<CertificateExtension>> extensions;
    std::vector<const CertificateExtension*> extensionPointers;

    BigInt serialNumber;
    Time notBefore;
    Time notAfter;

    Impl() {
      x509 = X509_new();
    }

    void fromDer(const std::vector<unsigned char> der) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      auto ret = d2i_X509_bio(mem, &x509);
      if (ret) {
        success = true;
        resetValues();
      } else {
        ERR_print_errors_fp (stderr);
      }
    }

    virtual ~Impl() {
      X509_free(x509);
      x509 = nullptr;
    }

    void resetValues() {
      resetSubjectIdentity();
      resetIssuerIdentity();
      resetPublicKey();
      resetValidity();
      resetSerialNumber();
      resetExtensions();
    }

    void resetSubjectIdentity() {
       auto name = X509_get_subject_name(x509);
       auto der = Converters::nameToIdentityDer(name);
       subjectIdentity.reset(Identity::fromDer(der));
    }

    void resetIssuerIdentity() {
       auto name = X509_get_issuer_name(x509);
       auto der = Converters::nameToIdentityDer(name);
       issuerIdentity.reset(Identity::fromDer(der));
    }

    void resetSerialNumber() {
      auto sn = X509_get_serialNumber(x509);
      auto bn = ASN1_INTEGER_to_BN(sn, NULL);
      auto dec = Converters::bnToString(bn);
      BN_free(bn);
      serialNumber = dec;
    }

    void resetPublicKey() {
      auto evp = X509_get_pubkey(x509);
      if (evp) {
        auto der = Converters::rsaToPublicKeyDer(evp->pkey.rsa);
        EVP_PKEY_free(evp);
        publicKey.reset(RsaPublicKey::fromDer(der));
      }
    }

    void resetValidity() {
      auto certInfo = x509->cert_info;
      if (!certInfo) {
        return;
      }

      auto validity = certInfo->validity;
      if (!validity) {
        return;
      }

      if (!(validity->notBefore && validity->notAfter)) {
        return;
      }

      auto cBefore = (char*) ASN1_STRING_data((ASN1_STRING*) validity->notBefore);
      if (!cBefore) {
        return;
      }
      std::string sBefore = cBefore;
      Time tBefore(sBefore);

      auto cAfter = (char *) ASN1_STRING_data((ASN1_STRING*) validity->notAfter);
      if (!cAfter) {
        return;
      }
      std::string sAfter = cAfter;
      Time tAfter(sAfter);

      notBefore = tBefore;
      notAfter = tAfter;

    }

    void resetExtensions() {
      extensions.clear();
      resetSKID();
    }

    void resetSKID() {
      auto pos = X509_get_ext_by_NID(x509, NID_subject_key_identifier, 0);
      if (pos < 0) return;

      auto ext = X509_get_ext(x509, pos);
      auto length = ASN1_STRING_length((ASN1_STRING*) ext->value);
      std::vector<unsigned char> skid(length);
      std::transform(ext->value->data, ext->value->data + length, skid.begin(),
          [](char c)
          {
          return static_cast<unsigned char>(c);
          });

      std::unique_ptr<CertificateExtension> c;
      c.reset(new CertificateSubjectKeyIdentifierExtension(skid));
      extensions.push_back(std::move(c));
    }

};

Certificate::Certificate() : impl{std::make_unique<Impl>()} {
}

Certificate::~Certificate() {
}

const Identity& Certificate::subjectIdentity() const {
  return *impl->subjectIdentity.get();
}

const Identity& Certificate::issuerIdentity() const {
  return *impl->issuerIdentity.get();
}

const BigInt& Certificate::serialNumber() const {
  return impl->serialNumber;
}

const RsaPublicKey& Certificate::publicKey() const {
  return *impl->publicKey.get();
}

KeyUsage Certificate::keyUsage() const {
  return (KeyUsage) impl->x509->ex_kusage;
}

ExtendedKeyUsage Certificate::extendedKeyUsage() const {
  return (ExtendedKeyUsage) impl->x509->ex_xkusage;
}

const Time& Certificate::notBefore() const {
  return impl->notBefore;
}

const Time& Certificate::notAfter() const {
  return impl->notAfter;
}

Certificate* Certificate::fromDer(const std::vector<unsigned char> der) {
  Certificate* cert = new Certificate();
  cert->impl->fromDer(der);

  if (cert->impl->success == false) {
    delete(cert);
    return nullptr;
  }

  return cert;
}

const std::vector<const CertificateExtension*>& Certificate::extensions() const {
  impl->extensionPointers.clear();
  for (unsigned int i = 0; i < impl->extensions.size(); i ++) {
    impl->extensionPointers.push_back(impl->extensions.at(i).get());
  }
  return impl->extensionPointers;
}

// CertificateExtensions -----------------------------------------------------

class CertificateSubjectKeyIdentifierExtension::Impl {
  public:
    std::vector<unsigned char> subjectKeyIdentifier;
    std::unique_ptr<ObjectId> oid;

    Impl(const std::vector<unsigned char> der) : oid{std::make_unique<ObjectId>("2.5.29.14")} {
      long xlen;
      int tag, xclass;
      const unsigned char* skid = (const unsigned char*) der.data();
      ASN1_get_object(&skid, &xlen, &tag, &xclass, der.size());

      subjectKeyIdentifier.clear();
      for (int i = 0; i < xlen; i ++) {
        subjectKeyIdentifier.push_back(skid[i]);
      }
    }

    virtual ~Impl() {

    }
};


CertificateSubjectKeyIdentifierExtension::CertificateSubjectKeyIdentifierExtension(const std::vector<unsigned char> der) : impl{std::make_unique<Impl>(der)} {
}

const std::vector<unsigned char> CertificateSubjectKeyIdentifierExtension::value() const {
  return impl->subjectKeyIdentifier;
}

const ObjectId& CertificateSubjectKeyIdentifierExtension::objectId() const {
  return *impl->oid.get();
}

} // namespace Erpiko
