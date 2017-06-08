#include "erpiko/tsa.h"
#include "converters.h"
#include <openssl/ts.h>
#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>
#include <iostream>

namespace Erpiko {

  static ASN1_INTEGER *xSerialCb(struct TS_resp_ctx *, void *);

  class TsaResponse::ImplResponse {
    public:

      TsaResponseStatus::Status status = TsaResponseStatus::UNINITIALIZED;
      bool readOnly = true;
      std::vector<unsigned char> importedDer;
      std::vector<unsigned char> request;
      std::function<long(void)> serialCb = nullptr;

      TS_RESP_CTX *ctx;
      TS_RESP *response = nullptr;
      char *section;

      EVP_PKEY *pkey = nullptr;
      X509 *cert = nullptr;

      ~ImplResponse() {
        TS_RESP_CTX_free(ctx);
        if (pkey) {
          EVP_PKEY_free(pkey);
        }
        if (cert) {
          X509_free(cert);
        }

        if (response) {
          TS_RESP_free(response);
        }
      }

      ImplResponse() {
        OpenSSL_add_all_digests();
        OpenSSL_add_all_algorithms();
        ctx = TS_RESP_CTX_new();

        ObjectId sha1("1.3.14.3.2.26");
        ObjectId sha256("2.16.840.1.101.3.4.2.1");
        addAlgorithm(sha1);
        addAlgorithm(sha256);

        ObjectId pol("1.3.6.1.4.1.13762.3");
        addPolicy(pol, true);
      }

      void init(std::vector<unsigned char> data, std::vector<unsigned char> req) {
        readOnly = true;
        importedDer = data;

        BIO* mem = BIO_new_mem_buf((void*) data.data(), data.size());
        request = req;
        response = d2i_TS_RESP_bio(mem, NULL);
        if (response) {
          status = TsaResponseStatus::SUCCESS;
        }
        BIO_free(mem);
      }

      void init(const Certificate& certificate, const RsaKey& privateKey, std::vector<unsigned char> req) {
        readOnly = false;
        pkey = Converters::rsaKeyToPkey(privateKey);
        cert = Converters::certificateToX509(certificate);
        if (!TS_RESP_CTX_set_signer_key(ctx, pkey)) {
          status = TsaResponseStatus::INVALID_KEY;
          return;
        }
        if (!TS_RESP_CTX_set_signer_cert(ctx, cert)) {
          status = TsaResponseStatus::INVALID_CERT;
          return;
        }
        request = req;
        status = TsaResponseStatus::SUCCESS;
      }

      std::vector<unsigned char> toDer() {
        if (status != TsaResponseStatus::SUCCESS) {
          std::vector<unsigned char> ret;
          return ret;
        }
        if (readOnly) return importedDer;

        auto req = BIO_new_mem_buf((void*) request.data(), request.size());
        response = TS_RESP_create_response(ctx, req);

        std::vector<unsigned char> retval;
        int ret;
        BIO* mem = BIO_new(BIO_s_mem());

        ret = i2d_TS_RESP_bio(mem, response);

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

      bool addAlgorithm(const ObjectId &algo) {
        bool retval = false;
        auto obj = OBJ_txt2obj(algo.toString().c_str(), 1);
        if (obj) {
          auto md = const_cast<EVP_MD*>(EVP_get_digestbyobj(obj));
          ASN1_OBJECT_free(obj);
          TS_RESP_CTX_add_md(ctx, md);
          return true;
        }
        return retval;
      }

      bool addPolicy(const ObjectId &policy, bool defaultPolicy) {
        bool retval = false;
        auto obj = OBJ_txt2obj(policy.toString().c_str(), 1);
        if (obj) {
          if (defaultPolicy) {
            TS_RESP_CTX_set_def_policy(ctx, obj);
          } else {
            TS_RESP_CTX_add_policy(ctx, obj);
          }
          ASN1_OBJECT_free(obj);
          return true;
        }
        return retval;
      }

      long serialCallback() {
        if (serialCb) {
          return serialCb();
        }
        return 1;
      }

      long serialNumber() {
        if (!response) return 0;

        auto info = response->tst_info;
        if (info) {
          auto s = TS_TST_INFO_get_serial(info);
          return ASN1_INTEGER_get(s);
        }
        return 0;
      }

      TsaVerificationStatus::Value verifyResponse() const {
        TsaVerificationStatus::Value status = TsaVerificationStatus::UNKNOWN;

        TS_VERIFY_CTX* v = TS_VERIFY_CTX_new();
        if (v && response) {
          TS_VERIFY_CTX_init(v);
          v->flags = TS_VFY_ALL_IMPRINT;
          if (TS_RESP_verify_response(v, response)) {
            status = TsaVerificationStatus::VERIFIED;
          } else {
            status = TsaVerificationStatus::NOT_VERIFIED;
          }
          TS_VERIFY_CTX_free(v);
        }

        return status;

      }

      TsaVerificationStatus::Value verifyToken(const Certificate &certificate,
          const std::string caFile) const {
        TsaVerificationStatus::Value retval = TsaVerificationStatus::UNKNOWN;

        int flags = TS_VFY_VERSION;
        TS_VERIFY_CTX* v = TS_VERIFY_CTX_new();
        if (v && response && response->token) {
          TS_VERIFY_CTX_init(v);
          if (!v->certs) {
            v->certs = sk_X509_new_null();
          }
          auto cert = Converters::certificateToX509(certificate);

          sk_X509_push(v->certs, cert);
          if (!v->store) {
            v->store = X509_STORE_new();
          }
          if (!caFile.empty()) {
            auto lookup = X509_STORE_add_lookup(v->store, X509_LOOKUP_file());
            X509_LOOKUP_load_file(lookup, caFile.c_str(), X509_FILETYPE_PEM);
          }

          flags |= TS_VFY_SIGNATURE;
          auto req = TsaRequest::fromDer(request);
          if (!req) {
            return retval;
          }

          if (req->noNonce() == false) {
            flags |= TS_VFY_NONCE;
            ASN1_INTEGER* nonce;

            auto raw = req->nonceValue().dump();
            auto bn = BN_bin2bn(raw.data(), raw.size(), nullptr);

            nonce = BN_to_ASN1_INTEGER(bn, nullptr);

            v->nonce = nonce;
          }

          flags |= TS_VFY_IMPRINT;
          auto imprint = Utils::hexString(req->digest());
          long len = imprint.length()/2;
          v->imprint = string_to_hex(imprint.c_str(), &len);
          v->imprint_len = len;


          v->flags = flags;
          int vresp = TS_RESP_verify_response(v, response);
          if (vresp == 1) {
            retval = TsaVerificationStatus::VERIFIED;
          } else {
            retval = TsaVerificationStatus::NOT_VERIFIED;
          }
          TS_VERIFY_CTX_free(v);

        }

        return retval;

      }

  };


static ASN1_INTEGER *xSerialCb(struct TS_resp_ctx *ctx, void *r) {
  TsaResponse* resp = (TsaResponse*) r;
  long ret = resp->serialCallback();

  ASN1_INTEGER *serial = ASN1_INTEGER_new();

  if (serial &&
      ASN1_INTEGER_set(serial, ret)) {
    return serial;
  }

  TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
      "Error during serial number generation.");
  return nullptr;

}

TsaResponse::TsaResponse() :
  impl{std::make_unique<ImplResponse>() }
{
}

TsaResponse::TsaResponse(const Certificate& certificate,
    const RsaKey& privateKey,
    std::vector<unsigned char> request) :
  impl{std::make_unique<ImplResponse>() }
{
  impl->init(certificate, privateKey, request);
  TS_RESP_CTX_set_serial_cb(impl->ctx, xSerialCb, this);
}

TsaResponse::~TsaResponse()
{
}

bool
TsaResponse::isReadOnly()
{
  return impl->readOnly;
}

PkiStatus::Value
TsaResponse::pkiStatusInfo() {
  if (impl->response &&
      impl->response->status_info &&
      impl->response->status_info->status) {
    return (PkiStatus::Value) ASN1_INTEGER_get(impl->response->status_info->status);
  }

  return PkiStatus::UNKNOWN;
}

PkiFailureInfo::Value
TsaResponse::pkiFailureInfo() {
  auto v = pkiStatusInfo();
  if (v == PkiStatus::GRANTED ||
      v == PkiStatus::GRANTED_WITH_MODS) {
    return PkiFailureInfo::NOT_FAILURE;
  }

  unsigned int ret = 0;
  for (unsigned int i = 0; i < 16; i ++) {
    if (ASN1_BIT_STRING_get_bit(impl->response->status_info->failure_info, i)) {
      ret = i;
      break;
    }
  }

  return (PkiFailureInfo::Value) ret;
}


const std::vector<unsigned char>
TsaResponse::toDer() {
  return impl->toDer();
}

TsaResponse*
TsaResponse::fromDer(std::vector<unsigned char> data, std::vector<unsigned char> request) {
  TsaResponse* r = new TsaResponse();
  r->impl->init(data, request);
  return r;
}



bool
TsaResponse::addAlgorithm(const ObjectId& algo)
{
  return impl->addAlgorithm(algo);
}

TsaResponseStatus::Status
TsaResponse::status() const {
  return impl->status;
}

void
TsaResponse::setSerialNumberGenerator(std::function<long(void)> cb) {
  impl->serialCb = cb;
}


long
TsaResponse::serialCallback() {
  return impl->serialCallback();
}

long
TsaResponse::serialNumber() {
  return impl->serialNumber();
}

TsaVerificationStatus::Value
TsaResponse::verifyToken(const Certificate &certificate, const std::string caFile) const {
  return impl->verifyToken(certificate, caFile);
}

TsaVerificationStatus::Value
TsaResponse::verifyToken(const Certificate &certificate) const {
  const std::string caFile;
  return impl->verifyToken(certificate, caFile);
}



} // namespace Erpiko
