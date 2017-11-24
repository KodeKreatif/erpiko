#include "erpiko/utils.h"
#include "erpiko/certificate.h"
#include "erpiko/certificate-extension.h"
#include "converters.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <algorithm>

namespace Erpiko {
class Certificate::Impl {
  public:
    X509* x509;
    X509_CRL* x509_CRL;
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
      x509_CRL = X509_CRL_new();
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

    void crlFromDer(const std::vector<unsigned char> der) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      auto ret = d2i_X509_CRL_bio(mem, &x509_CRL);
      if (ret) {
        success = true;
        resetValues();
      } else {
        ERR_print_errors_fp (stderr);
      }
      delete(mem);
    }

    void fromPem(const std::string pem) {
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      auto ret = PEM_read_bio_X509(mem, &x509, NULL, NULL);
      if (ret) {
        success = true;
        resetValues();
      }
      delete(mem);
    }

    virtual ~Impl() {
      X509_free(x509);
      x509 = nullptr;
      X509_CRL_free(x509_CRL);
      x509_CRL = nullptr;
    }

    // Copy values from our structure to X509
    void updateValues(const RsaKey& signerKey) {
      X509_set_version(x509, 2);
      updateValidity();
      updateIdentities();
      updateSerialNumber();
      updatePublicKey(signerKey);
    }

    void updatePublicKey(const RsaKey& signerKey) {
      if (!publicKey.get()) return;
      auto rsa = RSA_new();
      auto der = publicKey.get()->toDer();
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      if (mem && d2i_RSA_PUBKEY_bio(mem, &rsa)) {
        EVP_PKEY* pub = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pub, rsa);
        X509_set_pubkey(x509, pub);

        BIO_free(mem);
        mem = nullptr;

        X509V3_CTX ext_ctx;
        X509V3_set_ctx(&ext_ctx, x509, x509, nullptr, nullptr, 0);
        X509V3_set_nconf(&ext_ctx, nullptr);

        auto digest = EVP_sha256();
        EVP_MD_CTX mctx;
        EVP_MD_CTX_init(&mctx);
        EVP_PKEY_CTX *pkctx = nullptr;
        EVP_PKEY *pkey = EVP_PKEY_new();
        der = signerKey.toDer();
        mem = BIO_new_mem_buf((void*) der.data(), der.size());
        PKCS8_PRIV_KEY_INFO *p8inf;
        p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem, NULL);
        if (p8inf) {
          pkey = EVP_PKCS82PKEY(p8inf);
          PKCS8_PRIV_KEY_INFO_free(p8inf);
        }
        //BIO_free(mem);

        if (EVP_DigestSignInit(&mctx, &pkctx, digest, nullptr, pkey))
        if (X509_sign_ctx(x509, &mctx)) {
          EVP_MD_CTX_cleanup(&mctx);
        }
      }
      if (mem) {
        BIO_free(mem);
      }
    }

    void updateSerialNumber() {
      BIGNUM* b = BN_new();
      BN_hex2bn(&b, serialNumber.toHexString().c_str());
      ASN1_INTEGER* sn = BN_to_ASN1_INTEGER(b, nullptr);
      X509_set_serialNumber(x509, sn);
      ASN1_INTEGER_free(sn);
      BN_free(b);
    }

    void updateIdentities() {
      if (subjectIdentity) {
        X509_set_subject_name(x509, Converters::identityToName(*subjectIdentity.get()));
      }
      if (issuerIdentity) {
        X509_set_issuer_name(x509, Converters::identityToName(*issuerIdentity.get()));
      }
    }

    void updateValidity() {
      ASN1_TIME* t = ASN1_TIME_new();
      ASN1_TIME_set_string(t, notBefore.toString().c_str());
      X509_set_notBefore(x509, t);
      ASN1_TIME_set_string(t, notAfter.toString().c_str());
      X509_set_notAfter(x509, t);
      ASN1_TIME_free(t);
    }

    // Copy values from X509 structure to our structures
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
      c.reset(new CertificateSubjectKeyIdentifierExtension((ext->critical != -1), skid));
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

const std::string Certificate::crlDistPoint() const {
  std::vector<std::string> list;
  std::string result;
  int nid = NID_crl_distribution_points;
  STACK_OF(DIST_POINT) * dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(impl->x509, nid, NULL, NULL);
  if (sk_DIST_POINT_num(dist_points) < 1) {
    sk_DIST_POINT_free(dist_points);
    return std::string("");
  }
  DIST_POINT *dp = sk_DIST_POINT_value(dist_points, 0);
  DIST_POINT_NAME *distpoint = dp->distpoint;
  GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, 0);
  ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
  sk_DIST_POINT_free(dist_points);
  std::string uri = std::string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str));
  return uri;
}

CertificateRevocationState::State Certificate::isRevoked(const std::vector<unsigned char> issuerDer, const std::vector<unsigned char> crlDer) const {
  CertificateRevocationState::State status = CertificateRevocationState::UNKNOWN;

  Certificate* issuerCert = new Certificate();
  issuerCert->impl->fromDer(issuerDer);
  X509 * issuer = issuerCert->impl->x509;

  Certificate* crlCert = new Certificate();
  crlCert->impl->crlFromDer(crlDer);
  X509_CRL * crl = crlCert->impl->x509_CRL;
  if (issuer) {
    EVP_PKEY *issuerKey = X509_get_pubkey(issuer);
    ASN1_INTEGER *serial = X509_get_serialNumber(impl->x509);
    
    if (crl && issuerKey && X509_CRL_verify(crl, issuerKey)) {
      status = CertificateRevocationState::NOT_REVOKED;
      auto *revokedList = crl->crl->revoked;
      int revokedNum = sk_X509_REVOKED_num(revokedList);
      for (int j = 0; j < revokedNum && status == CertificateRevocationState::NOT_REVOKED; j++) {
        auto *entry = sk_X509_REVOKED_value(revokedList, j);
        if (entry->serialNumber->length == serial->length) {
          if (memcmp(entry->serialNumber->data, serial->data, serial->length) == 0) {
            status = CertificateRevocationState::REVOKED;
          }
        }
      }
    }
  }
  return status;
}

CertificateTrustState::State Certificate::isTrusted(const std::vector<unsigned char> rootCaDer, const std::vector<unsigned char> crlDer, const std::string& caChainPemPath) const {
  CertificateTrustState::State status = CertificateTrustState::UNKNOWN;
  STACK_OF(X509)* chain = sk_X509_new_null();

  Certificate* rootCaCert = new Certificate();
  rootCaCert->impl->fromDer(rootCaDer);
  X509 * issuer = rootCaCert->impl->x509;
  sk_X509_push(chain, issuer);

  Certificate* crlCert = new Certificate();
  crlCert->impl->crlFromDer(crlDer);
  X509_CRL * crl = crlCert->impl->x509_CRL;

  X509_STORE *store = X509_STORE_new();
  X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  X509_LOOKUP_load_file(lookup, caChainPemPath.c_str(), X509_FILETYPE_PEM);

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, impl->x509, chain);

  X509_STORE_add_crl(store, crl);
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

  int verifyResult = X509_verify_cert(ctx);
  X509_STORE_CTX_cleanup(ctx);
  X509_STORE_CTX_free(ctx);
  sk_X509_free(chain);
  status = CertificateTrustState::TRUSTED;
  if (verifyResult != 1) {
    status = CertificateTrustState::NOT_TRUSTED;
  }
  return status;
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

Certificate* Certificate::fromPem(const std::string pem) {
  Certificate* cert = new Certificate();
  cert->impl->fromPem(pem);

  if (cert->impl->success == false) {
    delete(cert);
    return nullptr;
  }

  return cert;
}



const std::vector<unsigned char> Certificate::toDer() const {
  return Converters::certificateToDer(impl->x509);
}

const std::string Certificate::toPem() const {
  return Converters::certificateToPem(impl->x509);
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
    bool critical;
    std::unique_ptr<ObjectId> oid;

    Impl(const bool critical, const std::vector<unsigned char> der) : critical(critical), oid{std::make_unique<ObjectId>("2.5.29.14")} {
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


CertificateSubjectKeyIdentifierExtension::CertificateSubjectKeyIdentifierExtension(const bool critical, const std::vector<unsigned char> der) : impl{std::make_unique<Impl>(critical, der)} {
}

const std::vector<unsigned char> CertificateSubjectKeyIdentifierExtension::value() const {
  return impl->subjectKeyIdentifier;
}

const ObjectId& CertificateSubjectKeyIdentifierExtension::objectId() const {
  return *impl->oid.get();
}

bool CertificateSubjectKeyIdentifierExtension::critical() const {
  return impl->critical;
}

//-------------------
class CertificateBasicConstraintsExtension::Impl {
  public:
    bool critical;
    std::unique_ptr<ObjectId> oid;
    bool isCa;
    unsigned int pathLengthConstraints;

    Impl(const bool critical, const std::vector<unsigned char> der) : critical(critical), oid{std::make_unique<ObjectId>("2.5.29.14")} {
      const unsigned char* raw = der.data();
      auto b = d2i_BASIC_CONSTRAINTS(0, &raw, der.size());
      isCa = b->ca;
      pathLengthConstraints = ASN1_INTEGER_get(b->pathlen);

    }

    virtual ~Impl() {

    }
};


CertificateBasicConstraintsExtension::CertificateBasicConstraintsExtension(const bool critical, const std::vector<unsigned char> der) : impl{std::make_unique<Impl>(critical, der)} {
}

const ObjectId& CertificateBasicConstraintsExtension::objectId() const {
  return *impl->oid.get();
}

bool CertificateBasicConstraintsExtension::critical() const {
  return impl->critical;
}

bool CertificateBasicConstraintsExtension::isCa() const {
  return impl->isCa;
}

unsigned int CertificateBasicConstraintsExtension::pathLengthConstraints() const {
  return impl->pathLengthConstraints;
}


Certificate*
Certificate::create(const Time& notBefore, const Time& notAfter, const Identity& subjectIdentity, const Identity& issuerIdentity, const BigInt& serialNumber, const RsaPublicKey& publicKey, const RsaKey& signerKey) {
  Certificate* c = new Certificate();
  c->impl->notBefore = notBefore;
  c->impl->notAfter = notAfter;
  c->impl->subjectIdentity.reset(Identity::fromDer(subjectIdentity.toDer()));
  c->impl->issuerIdentity.reset(Identity::fromDer(issuerIdentity.toDer()));
  c->impl->serialNumber = serialNumber;
  c->impl->publicKey.reset(RsaPublicKey::fromDer(publicKey.toDer()));
  c->impl->updateValues(signerKey);
  return c;
}

} // namespace Erpiko
