#include "erpiko/cmp.h"
#include "erpiko/utils.h"
#include "converters.h"
#include <openssl/err.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/x509.h>


namespace Erpiko {

class Cmp::Impl {
  public:
    CMP_CTX *cmpContext;
    EVP_PKEY *pkey = nullptr;
    X509_NAME* name = nullptr;
    X509* caCert = nullptr;

    std::unique_ptr<Certificate> clCert;

    Impl() {
      cmpContext = CMP_CTX_create();
    }

    virtual ~Impl() {
      CMP_CTX_delete(cmpContext);
      if (pkey) {
        EVP_PKEY_free(pkey);
      }
    }

};

Cmp::Cmp() : impl{std::make_unique<Impl>()} {
}

Cmp::~Cmp() = default;

void Cmp::serverPath(const std::string serverPath) {
  CMP_CTX_set1_serverPath(impl->cmpContext, serverPath.c_str());
}

void Cmp::serverPort(const int serverPort) {
  CMP_CTX_set1_serverPort(impl->cmpContext, serverPort);
}

void Cmp::referenceName(const std::string referenceName) {
  CMP_CTX_set1_referenceValue(impl->cmpContext, (const unsigned char*) referenceName.c_str(), referenceName.length());
}

void Cmp::secret(const std::string secretValue) {
  CMP_CTX_set1_secretValue(impl->cmpContext,  (const unsigned char*) secretValue.c_str(), secretValue.length());
}

void Cmp::serverName(const std::string serverName) {
  CMP_CTX_set1_serverName(impl->cmpContext, serverName.c_str());
}

void Cmp::privateKey(const RsaKey& privateKey) {
  impl->pkey = Converters::rsaKeyToPkey(privateKey);
  CMP_CTX_set0_newPkey(impl->cmpContext, impl->pkey);
}

void Cmp::subject(const Identity& identity) {
  impl->name = Converters::identityToName(identity);
  CMP_CTX_set1_subjectName(impl->cmpContext, impl->name);
}

void Cmp::caCertificate(const Certificate& cert) {
  impl->caCert = Converters::certificateToX509(cert);
  CMP_CTX_set1_srvCert(impl->cmpContext, impl->caCert);
}

const Certificate* Cmp::startInitRequest() {
  CMP_CTX_set1_timeOut(impl->cmpContext, 60);
  auto cert = CMP_doInitialRequestSeq(impl->cmpContext);
  ERR_print_errors_fp(stderr);
  if (!cert) return nullptr;
  auto der = Converters::certificateToDer(cert);

  impl->clCert.reset(Certificate::fromDer(der));
  return impl->clCert.get();

}

void Cmp::insertSim(const Sim& sim) {
  auto name = Converters::simToGeneralName(sim);
  CMP_CTX_subjectAltName_push1(impl->cmpContext, name);
  GENERAL_NAME_free(name);
}

} // namespace Erpiko
