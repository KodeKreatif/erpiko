#ifndef _DIGEST_OPENSSL_H
#define _DIGEST_OPENSSL_H

#include <memory>
#include <vector>
#include <openssl/evp.h>

namespace Erpiko {

class DigestOpenSsl {
  EVP_MD_CTX* ctx;
  int digestOp;
  bool valid;
  unsigned char hashValue[EVP_MAX_MD_SIZE];

  public:
    DigestOpenSsl(const char* objId) :
        ctx(EVP_MD_CTX_create()),
        valid(false) {
      OpenSSL_add_all_digests();
      OpenSSL_add_all_algorithms();
      auto obj = OBJ_txt2obj(objId, 1);
      auto hashAlgorithmMd = const_cast<EVP_MD*>(EVP_get_digestbyobj(obj));
      ASN1_OBJECT_free(obj);

      EVP_MD_CTX_init(ctx);
      digestOp = EVP_DigestInit(ctx, hashAlgorithmMd);
      if (digestOp) {
        valid = true;
      }

    }
    virtual ~DigestOpenSsl() {
      if (ctx) {
        EVP_MD_CTX_destroy(ctx);
      }
    };

    void update(std::vector<unsigned char> data) {
      if (!valid) return;
      digestOp = EVP_DigestUpdate(ctx, data.data(), data.size());
    }

    std::vector<unsigned char> finalize(std::vector<unsigned char> data) {
      std::vector<unsigned char> ret;
      if (!valid) return ret;
      unsigned int hashLength;

      if (data.size() > 0) {
        update(data);
      }
      digestOp = EVP_DigestFinal_ex(ctx, hashValue, &hashLength);
      if (hashLength > 0) {
        ret.assign(hashValue, hashValue + hashLength);
      }

      return ret;
    }
};

} // namespace Erpiko
#endif // _DIGEST_OPENSSL_H
