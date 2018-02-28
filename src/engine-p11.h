#ifndef _ENGINE_P11_H
#define _ENGINE_P11_H

#include <map>
#include <string>
#include <iostream>
#include "erpiko/token.h"
#include "erpiko/certificate.h"
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include "pkcs11/cryptoki.h"
#ifdef WIN32
#include <Windows.h>
#endif

using namespace std;

namespace Erpiko {

class EngineP11 {
  bool initialized = false;
#ifdef WIN32
  HMODULE lib = nullptr;
#else
  void* lib = nullptr;
#endif
  unsigned long session = 0;
  string keyLabel;
  // initially keyId is unsigned int
  std::vector<unsigned char> keyId;

  private:
    EngineP11() : defaultRsa(RSA_get_default_method()) {
    }

  public:
    static EngineP11& getInstance() {
      static EngineP11 me;

      return me;
    }

    EngineP11(EngineP11 const&) = delete;
    void operator=(EngineP11 const&) = delete;
    void init();
    bool load(const std::string path);
    void finalize();
    CardStatus::Value waitForCardStatus(int &slot);
    bool login(const unsigned long slot, const string& pin);
    bool logout();
    unsigned long getSession() {
      return session;
    }

    void setKeyLabel(const string& label) {
      keyLabel = label;
    }

    void setKeyId(const unsigned int id) {
      // make sure that keyId storage is cleared prior to assignment
      keyId.clear();
      keyId.push_back((id >> 24) & 0xFF);
      keyId.push_back((id >> 16) & 0xFF);
      keyId.push_back((id >> 8) & 0xFF);
      keyId.push_back((id >> 0) & 0xFF);

    }
    void setKeyId(const std::vector<unsigned char> id) {
      keyId = id;
    }

    void unsetKey() {
      keyId.clear();
      keyLabel = "";
    }

    const string& getKeyLabel() const {
      return keyLabel;
    }

    unsigned int getKeyId() const {
      // for backward compatibility, check if the vector byte size is less than size of uint32
      // it means as a drop in compatibility when keyId is unset = keyId = -1
      if (keyId.size() < sizeof(unsigned int))
        return -1;
      // Reconstruct back the unsigned integer from vector byte
      return keyId.at(3) | (keyId.at(2) << 8) | (keyId.at(1) << 16) | (keyId.at(0) << 24);
    }
    std::vector<unsigned char> getKeyIdVector() const {
      return keyId;
    }

    TokenOpResult::Value putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data, bool isUnique);
    std::vector<unsigned char> getData(const std::string& applicationName, std::string& label);
    std::vector<std::vector<unsigned char>> getAllData(const std::string& applicationName, std::string& label);
    bool removeData(const std::string& applicationName, const std::string& label);
    bool parseAttr(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE &attr, std::vector<unsigned char> *value = nullptr);
    std::vector<TokenInfo> getAllTokensInfo();
    std::vector<Certificate*> getCertificates(bool);
    TokenOpResult::Value putCertificate(const Certificate& cert);
    bool removeCertificate(const Certificate& cert);
    TokenOpResult::Value putPrivateKey(const RsaKey& data, const std::string& labelStr);
    bool removePrivateKey(const std::string& labelStr);
    RsaKey* getPrivateKey(const RsaPublicKey& publicKey);

    ENGINE *erpikoEngine = nullptr;
    ENGINE *erpikoDefault = nullptr;
    const RSA_METHOD* defaultRsa;
  };
} // namespace Erpiko
#endif // _ENGINE_P11_H
