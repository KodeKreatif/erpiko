#include "erpiko/certificate-request.h"
#include "converters.h"
#include <openssl/x509.h>

namespace Erpiko {

class CertificateRequest::Impl {

  X509_REQ* req = nullptr;
  std::unique_ptr<Identity> subjectIdentity;
  std::unique_ptr<RsaPublicKey> pubKey;

  public:
    bool valid = false;
    Impl() {
    }

    Impl(const Identity& subject, const RsaKey& key, const ObjectId& algorithm) : req(X509_REQ_new()){
      OpenSSL_add_all_algorithms();
      X509_REQ_set_subject_name(req, Converters::identityToName(subject));
      EVP_PKEY* pkey = Converters::rsaKeyToPkey(key);
      X509_REQ_set_pubkey(req, pkey);
      auto obj = OBJ_txt2obj(algorithm.toString().c_str(), 1);
      if (obj) {
        auto md = const_cast<EVP_MD*>(EVP_get_digestbyobj(obj));
        if (md) {
          if (X509_REQ_sign(req, pkey, md)) valid = true;
        }
      }
      EVP_PKEY_free(pkey);
    }

    virtual ~Impl() {
      if (req) {
        X509_REQ_free(req);
      }
    }

    const std::string toPem() const {
      if (!valid) {
        const std::string ret;
        return ret;
      }
      return Converters::certificateRequestToPem(req);
    }

    const std::vector<unsigned char> toDer() const {
      if (!valid) {
        const std::vector<unsigned char> ret;
        return ret;
      }
      return Converters::certificateRequestToDer(req);
    }

    void fromDer(const std::vector<unsigned char> der) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      auto ret = d2i_X509_REQ_bio(mem, &req);
      if (ret) {
        valid = true;
      } else {
        ERR_print_errors_fp (stderr);
      }
    }

    void fromPem(const std::string pem) {
      BIO* mem = BIO_new_mem_buf((void*) pem.c_str(), pem.length());
      auto ret = PEM_read_bio_X509_REQ(mem, &req, NULL, NULL);
      if (ret) {
        valid = true;
      }
      delete(mem);
    }

    const Identity& subject() {
      auto der = Converters::nameToIdentityDer(X509_REQ_get_subject_name(req));
      subjectIdentity.reset(Identity::fromDer(der));
      return *subjectIdentity.get();
    }

    const RsaPublicKey& publicKey() {
      auto pkey = X509_REQ_get_pubkey(req);
      auto der = Converters::rsaKeyToDer(pkey, "", true);
      pubKey.reset(RsaPublicKey::fromDer(der));
      return *pubKey.get();

    }

};

CertificateRequest::CertificateRequest() : impl{std::make_unique<Impl>()} {};
CertificateRequest::CertificateRequest(const Identity& subject, const RsaKey& key, const ObjectId& algorithm) : impl{std::make_unique<Impl>(subject, key, algorithm)} {};

CertificateRequest::~CertificateRequest() = default;

const std::string
CertificateRequest::toPem() const {
  return impl->toPem();
}

const std::vector<unsigned char>
CertificateRequest::toDer() const {
  return impl->toDer();
}

bool
CertificateRequest::isValid() const {
  return impl->valid;
}

CertificateRequest* CertificateRequest::fromDer(const std::vector<unsigned char> der) {
  CertificateRequest* req = new CertificateRequest();
  req->impl->fromDer(der);

  if (req->impl->valid == false) {
    delete(req);
    return nullptr;
  }

  return req;
}

CertificateRequest* CertificateRequest::fromPem(const std::string pem) {
  CertificateRequest* req = new CertificateRequest();
  req->impl->fromPem(pem);

  if (req->impl->valid == false) {
    delete(req);
    return nullptr;
  }

  return req;
}

const Identity&
CertificateRequest::subject() const {
  return impl->subject();
}

const RsaPublicKey&
CertificateRequest::publicKey() const {
  return impl->publicKey();
}
} // namespace Erpiko
