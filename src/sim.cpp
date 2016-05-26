#include "erpiko/sim.h"
#include "erpiko/utils.h"
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "sim-openssl.h"

namespace Erpiko {
class Sim::Impl {

  public:
  EVP_MD* hashAlgorithmMd;

  unsigned int bitSize = 0;
  std::unique_ptr<ObjectId> hashAlgorithm;
  std::unique_ptr<ObjectId> siiType;
  std::string sii;
  std::string password;
  std::vector<unsigned char> authorityRandom;
  bool valid = false;


  Impl(const ObjectId& hashAlgorithm, const ObjectId& siiType, const std::string sii, const std::string password, const std::vector<unsigned char> authorityRandom) :
    hashAlgorithm(std::make_unique<ObjectId>(hashAlgorithm.toString())),
    siiType(std::make_unique<ObjectId>(siiType.toString())),
    sii(sii),
    password(password),
    authorityRandom(authorityRandom)
  {
    checkAlgo();
  }

  void checkAlgo() {
    if (hashAlgorithm->toString() == "2.16.840.1.101.3.4.2.1") {
      bitSize = 32;
      if (authorityRandom.size() == bitSize) {
        hashAlgorithmMd = (EVP_MD*) EVP_sha256();
        valid = true;
      }
    }
  }

  std::vector<unsigned char> pepsi() {
    std::vector<unsigned char> retval;
    std::vector<unsigned char> pepsiDer;
    SIM_PEPSI *pepsi = SIM_PEPSI_new();

    ASN1_STRING_set((ASN1_STRING*)pepsi->userPassword, password.c_str(), password.length());
    ASN1_STRING_set((ASN1_STRING*)pepsi->sii, sii.c_str(), sii.length());
    ASN1_OCTET_STRING_set(pepsi->authorityRandom, authorityRandom.data(), authorityRandom.size());
    ASN1_OBJECT_free(pepsi->siiType);
    pepsi->siiType = OBJ_txt2obj(siiType->toString().c_str(), 1);
    auto length = i2d_SIM_PEPSI(pepsi, 0);
    if (length > 0) {
      unsigned char *der = (unsigned char*)malloc(length);
      unsigned char *start = der;
      i2d_SIM_PEPSI(pepsi, &der);
      for (int i = 0; i < length; i ++) {
        pepsiDer.push_back(start[i]);
      }
      free(start);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    auto digestOp = EVP_DigestInit(ctx, hashAlgorithmMd);

    if (digestOp == 0) {
      return retval;
    }
    digestOp = EVP_DigestUpdate(ctx, pepsiDer.data(), pepsiDer.size());
    if (digestOp == 0) {
      return retval;
    }
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashLength;
    digestOp = EVP_DigestFinal_ex(ctx, hashValue, &hashLength);
    if (digestOp == 0) {
      return retval;
    }
    // second turn
    digestOp = EVP_DigestInit(ctx, hashAlgorithmMd);
    if (digestOp == 0) {
      return retval;
    }

    digestOp = EVP_DigestUpdate(ctx, hashValue, hashLength);
    if (digestOp == 0) {
      return retval;
    }
    unsigned char hashValueFinal[EVP_MAX_MD_SIZE];
    unsigned int hashLengthFinal;
    digestOp = EVP_DigestFinal_ex(ctx, hashValueFinal, &hashLengthFinal);
    if (digestOp == 0) {
      return retval;
    }
    for (unsigned int i = 0; i < hashLengthFinal; i ++) {
      retval.push_back(hashValueFinal[i]);
    }

    SIM_PEPSI_free(pepsi);
    return retval;
  }

  SIM* sim() {
    std::vector<unsigned char> pepsiDer = pepsi();
    SIM *sim = SIM_new();

    X509_ALGOR_set_md(sim->hashAlgorithm, hashAlgorithmMd);
    ASN1_OCTET_STRING_set(sim->authorityRandom, authorityRandom.data(), authorityRandom.size());
    ASN1_OCTET_STRING_set(sim->pepsi, pepsiDer.data(), pepsiDer.size());
    return sim;
  }

  std::vector<unsigned char> value() {
    std::vector<unsigned char> retval;
    auto sim = this->sim();
    auto length = i2d_SIM(sim, 0);
    if (length > 0) {
      unsigned char *der = (unsigned char*)malloc(length);
      unsigned char *start = der;
      i2d_SIM(sim, &der);
      for (int i = 0; i < length; i ++) {
        retval.push_back(start[i]);
      }
      free(start);
    }
    SIM_free(sim);
    return retval;
  }

  std::vector<unsigned char> epepsi() {
    std::vector<unsigned char> retval;
    SIM_EPEPSI *epepsi = SIM_EPEPSI_new();

    ASN1_OBJECT_free(epepsi->siiType);
    epepsi->siiType = OBJ_txt2obj(siiType->toString().c_str(), 1);
    ASN1_STRING_set((ASN1_STRING*)epepsi->sii, sii.c_str(), sii.length());
    epepsi->sim = this->sim();
    auto length = i2d_SIM_EPEPSI(epepsi, 0);
    if (length > 0) {
      unsigned char *der = (unsigned char*)malloc(length);
      unsigned char *start = der;
      i2d_SIM_EPEPSI(epepsi, &der);
      for (int i = 0; i < length; i ++) {
        retval.push_back(start[i]);
      }
      free(start);
    }
    SIM_EPEPSI_free(epepsi);
    return retval;
  }

  ~Impl() = default;
};

Sim::Sim(const ObjectId& hashAlgorithm, const ObjectId& siiType, const std::string sii, const std::string password, const std::vector<unsigned char> authorityRandom) :
  impl{std::make_unique<Impl>(hashAlgorithm, siiType, sii, password, authorityRandom) } {
}

Sim::~Sim() = default;

bool Sim::isValid() {
  return impl->valid;
}

const std::vector<unsigned char> Sim::pepsi() const {
  return impl->pepsi();
}

const std::vector<unsigned char> Sim::toDer() const {
  return impl->value();
}

const std::vector<unsigned char> Sim::epepsi() const {
  return impl->epepsi();
}


const ObjectId& Sim::siiType() const {
  return *impl->siiType.get();
}

} // namespace Erpiko
