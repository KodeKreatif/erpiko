#include "erpiko/tsa.h"
#include "erpiko/bigint.h"
#include <openssl/evp.h>
#include <openssl/ts.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <compat/stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iostream>

namespace Erpiko {

  class TsaRequest::Impl {
    public:
      bool valid = false;
      std::unique_ptr<ObjectId> hashAlgorithm;
      std::unique_ptr<ObjectId> policyId;
      bool noNonce;
      BigInt nonceValue;
      bool includeCertificate;
      EVP_MD_CTX* ctx;

      EVP_MD* hashAlgorithmMd;
      int digestOp;

      unsigned char hashValue[EVP_MAX_MD_SIZE];
      unsigned int hashLength;
      TS_REQ *tsReq = nullptr;
      TS_MSG_IMPRINT *msgImprint = nullptr;
      X509_ALGOR *algo = nullptr;
      ASN1_OBJECT *policyObj = nullptr;
      ASN1_INTEGER *nonceAsn1 = nullptr;

      std::vector<unsigned char> importedDer;

      Impl() :
        hashAlgorithm(std::make_unique<ObjectId>("0.0.0.0")),
        tsReq(TS_REQ_new()),
        msgImprint(TS_MSG_IMPRINT_new())
    {
    }

      Impl(const ObjectId& hashAlgorithm) :
        hashAlgorithm(std::make_unique<ObjectId>(hashAlgorithm.toString())),
        policyId(std::make_unique<ObjectId>("0.0.0.0")),
        noNonce(false),
        includeCertificate(false),
        ctx(EVP_MD_CTX_create()),
        hashLength(0),
        tsReq(TS_REQ_new()),
        msgImprint(TS_MSG_IMPRINT_new()),
        algo(X509_ALGOR_new()),
        nonceAsn1(ASN1_INTEGER_new())
    {

      OpenSSL_add_all_digests();
      OpenSSL_add_all_algorithms();

      auto obj = OBJ_txt2obj(hashAlgorithm.toString().c_str(), 1);
      hashAlgorithmMd = const_cast<EVP_MD*>(EVP_get_digestbyobj(obj));
      ASN1_OBJECT_free(obj);

      EVP_MD_CTX_init(ctx);
      digestOp = EVP_DigestInit(ctx, hashAlgorithmMd);
      if (digestOp) {
        valid = true;
      }

    }

    ~Impl() {
      if (ctx) {
        EVP_MD_CTX_destroy(ctx);
      }

      if (msgImprint != nullptr) {
        TS_MSG_IMPRINT_free(msgImprint);
        msgImprint = nullptr;
      }
      if (algo != nullptr) {
        X509_ALGOR_free(algo);
        algo = nullptr;
      }
      if (policyObj != nullptr) {
        ASN1_OBJECT_free(policyObj);
        policyObj = nullptr;
      }
      if (nonceAsn1 != nullptr) {
        ASN1_INTEGER_free(nonceAsn1);
        nonceAsn1 = nullptr;
      }

    }

    void update(const unsigned char* data, const size_t length) {
      if (!valid) { return; };
      digestOp = EVP_DigestUpdate(ctx, data, length);
    }

    void setAlgo() {
      if (!valid) { return; };
      if (algo == nullptr || msgImprint == nullptr) {
        return;
      }
      algo->algorithm = OBJ_nid2obj(EVP_MD_type(hashAlgorithmMd));
      algo->parameter = ASN1_TYPE_new();
      if (!algo->parameter) {
        return;
      }
      algo->parameter->type = V_ASN1_NULL;

      TS_MSG_IMPRINT_set_algo(msgImprint, algo);
    }

    void setPolicy() {
      if (policyId && policyId.get()->toString() != "0.0.0.0") {
        policyObj = OBJ_txt2obj(policyId.get()->toString().c_str(), 1);
        TS_REQ_set_policy_id(tsReq, policyObj);
      }
    }

    void setNonce() {
      if (noNonce) {
        return;
      }
      unsigned char buf[20];
      int len = (64 - 1) / 8 + 1;
      int i;

      i = RAND_bytes(buf, len);

      for (i = 0; i < len && !buf[i]; ++i) ;
      free(nonceAsn1->data);
      nonceAsn1->length = len - i;
      nonceAsn1->data = (unsigned char*)malloc(nonceAsn1->length + 1);

      if (nonceAsn1->data) {
        memcpy(nonceAsn1->data, buf + i, nonceAsn1->length);
        TS_REQ_set_nonce(tsReq, nonceAsn1);
        auto bn = ASN1_INTEGER_to_BN(nonceAsn1, nullptr);
        auto str = BN_bn2hex(bn);
        std::string bnStr("0x");
        auto bn2 = BigInt::fromString(bnStr + str);
        BN_free(bn);

        nonceValue = *bn2;
      }
    }

    void done() {
      if (!valid) { return; };
      digestOp = EVP_DigestFinal_ex(ctx, hashValue, &hashLength);

      TS_REQ_set_version(tsReq, 1);
      setAlgo();

      TS_MSG_IMPRINT_set_msg(msgImprint, hashValue, hashLength);
      TS_REQ_set_msg_imprint(tsReq, msgImprint);
      setPolicy();
      setNonce();
      TS_REQ_set_cert_req(tsReq, includeCertificate ? 1 : 0);

    }

    const std::vector<unsigned char> toDer() {
      if (importedDer.size() > 0) {
        return importedDer;
      }
      done();
      std::vector<unsigned char> retval;
      BIO* bio = BIO_new(BIO_s_mem());
      i2d_TS_REQ_bio(bio, tsReq);

      while (true) {
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

      BIO_free(bio);
      return retval;
    }

    void fromDer(const std::vector<unsigned char> der) {
      BIO* mem = BIO_new_mem_buf((void*) der.data(), der.size());
      tsReq = d2i_TS_REQ_bio(mem, NULL);

      nonceAsn1 = tsReq->nonce;
      if (nonceAsn1) {
        auto bn = ASN1_INTEGER_to_BN(nonceAsn1, nullptr);
        auto str = BN_bn2hex(bn);
        std::string bnStr("0x");
        auto bn2 = BigInt::fromString(bnStr + str);

        nonceValue = *bn2;
        BN_free(bn);
        noNonce = false;
      } else {
        noNonce = true;
      }

      policyObj = tsReq->policy_id;
      msgImprint = tsReq->msg_imprint;

      char buffer[1024];
      OBJ_obj2txt(buffer, sizeof buffer, msgImprint->hash_algo->algorithm, 1);
      ObjectId *o = new ObjectId(buffer);
      hashAlgorithm.reset(o);

      OBJ_obj2txt(buffer, sizeof buffer, policyObj, 1);

      o = new ObjectId(buffer);
      policyId.reset(o);

      auto hash = msgImprint->hashed_msg;
      hashLength = hash->length;
      for (unsigned int i = 0; i < hashLength; i++) {
        hashValue[i] = hash->data[i];
      }

      includeCertificate = tsReq->cert_req;

      importedDer = der;
    }
};

TsaRequest::TsaRequest(const ObjectId& hashAlgorithm) :
  impl{std::make_unique<Impl>(hashAlgorithm) }
{

}

void TsaRequest::setPolicyId(const ObjectId& policyId) {
  ObjectId *o = new ObjectId(policyId.toString());
  impl->policyId.reset(o);
}

void TsaRequest::setIncludeCertificate(bool value) {
  impl->includeCertificate = value;
}

void TsaRequest::setNoNonce(bool value) {
  impl->noNonce = value;
}

bool TsaRequest::includeCertificate() const {
  return impl->includeCertificate;
}

bool TsaRequest::noNonce() const {
  return impl->noNonce;
}

const ObjectId& TsaRequest::policyId() const {
  return *impl->policyId.get();
}

TsaRequest::~TsaRequest() {
  impl->hashAlgorithm.reset();
  impl->policyId.reset();
};


void
TsaRequest::update(const unsigned char* data, const size_t length) {
  impl->update(data, length);
}

void
TsaRequest::update(const std::vector<unsigned char> data) {
  update(data.data(), data.size());
}

const std::vector<unsigned char>
TsaRequest::toDer() {
  return impl->toDer();
}


TsaRequest*
TsaRequest::fromDer(const std::vector<unsigned char> der) {
  TsaRequest *r = new TsaRequest();
  r->impl->fromDer(der);
  return r;
}

TsaRequest::TsaRequest() :
  impl{std::make_unique<Impl>() }
{
}


const BigInt&
TsaRequest::nonceValue() const {
  return impl->nonceValue;
}

const ObjectId&
TsaRequest::hashAlgorithm() const {
  return *impl->hashAlgorithm.get();
}

std::vector<unsigned char>
TsaRequest::digest() const {
  std::vector<unsigned char> retval;
  retval.assign(impl->hashValue, impl->hashValue + impl->hashLength);
  return retval;
}
} // namespace Erpiko
