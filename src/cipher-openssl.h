#ifndef _CIPHER_OPENSSL_H
#define _CIPHER_OPENSSL_H

#include <memory>
#include <vector>
#include <iostream>
#include <openssl/evp.h>
#include "erpiko/cipher.h"

namespace Erpiko {

class CipherOpenSsl : public Cipher {
  EVP_CIPHER_CTX* ctx;
  int cipherOp;
  bool valid = false;

  public:
    bool isValid() {
      return valid;
    }

    CipherOpenSsl(const char* objId, CipherConstants::Mode mode, std::vector<unsigned char> key, std::vector<unsigned char> iv) :
      Cipher(mode, key, iv),
      ctx(EVP_CIPHER_CTX_new())
      {
      OpenSSL_add_all_digests();
      OpenSSL_add_all_algorithms();
      auto cipher = EVP_get_cipherbyname(objId);
      if (!cipher) {
        auto obj = OBJ_txt2obj(objId, 1);
        cipher = const_cast<EVP_CIPHER*>(EVP_get_cipherbyobj(obj));
        ASN1_OBJECT_free(obj);
        if (!cipher) {
        std::cerr << objId << std::endl;
          return;
        }
      }

      EVP_CIPHER_CTX_init(ctx);
      if (key.size () > 0) {
     //   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, key.size() * 8, nullptr);
      }
      if (iv.size() > 0) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size() * 8, nullptr);
      }
      cipherOp = EVP_CipherInit_ex(ctx, cipher, NULL, key.data(), iv.data(), mode);
      if (cipherOp) {
        valid = true;
      }

    }
    virtual ~CipherOpenSsl() {
      if (ctx) {
        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);
      }
    };

    std::vector<unsigned char> update(std::vector<unsigned char> data) {
      std::vector<unsigned char> ret;
      if (!valid) return ret;
      unsigned char* buffer = new unsigned char[data.size() + EVP_CIPHER_CTX_block_size(ctx)];
      int bufferLength;
      cipherOp = EVP_CipherUpdate(ctx, buffer, &bufferLength, data.data(), data.size());
      if (cipherOp == 0) {
        delete buffer;
        return ret;
      }

      if (bufferLength > 0) {
        ret.assign(buffer, buffer + bufferLength);
      }
      delete buffer;
      return ret;
    }

    std::vector<unsigned char> finalize() {
      std::vector<unsigned char> ret;
      if (!valid) return ret;
      unsigned char buffer[1024];
      int bufferLength;

      cipherOp = EVP_CipherFinal_ex(ctx, buffer, &bufferLength);
      if (cipherOp == 0) {
        return ret;
      }
      if (bufferLength > 0) {
        ret.assign(buffer, buffer + bufferLength);
      }

      return ret;
    }

    void enablePadding(bool enabled) {
      EVP_CIPHER_CTX_set_padding(ctx, enabled);
    }

    void setTag(std::vector<unsigned char> tag) {
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());
    }

    std::vector<unsigned char> getTag() {
      char buffer[16];
      std::vector<unsigned char> tag(sizeof(buffer));

      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(buffer), buffer);
      tag.assign(buffer, buffer + sizeof(buffer));

      return tag;
    }

    void setAad(std::vector<unsigned char> aad) {
      int length;
      EVP_CipherUpdate(ctx, nullptr, &length, aad.data(), aad.size());
    }


};

} // namespace Erpiko
#endif // _CIPHER_OPENSSL_H
