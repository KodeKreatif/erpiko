#ifndef _P11_TOKEN_H_
#define _P11_TOKEN_H_
#include "token.h"
namespace Erpiko {

class P11Token : Token {
  public:
    P11Token();
    virtual ~P11Token();
    virtual bool load(const std::string path);
    virtual void unload();
    virtual bool isValid();
    virtual CardStatus::Value waitForCardStatus(int &slot) const;
    virtual bool login(const unsigned long slot, const std::string& pin) const;
    virtual bool logout() const;
    virtual void setKeyId(const unsigned int id, const std::string& label);
    virtual void setKeyId(const unsigned int id);
    virtual void setKeyId(const std::vector<unsigned char> id);
    virtual void setKeyLabel(const std::string& label);
    virtual void unsetKey();
    virtual TokenOpResult::Value putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data);
    virtual TokenOpResult::Value putUniqueData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data);
    virtual std::vector<unsigned char> getData(const std::string& applicationName, std::string& label);
    virtual std::vector<std::vector<unsigned char>> getAllData(const std::string& applicationName, std::string& label);
    virtual std::vector<TokenInfo> getAllTokensInfo();
    virtual bool removeData(const std::string& applicationName, const std::string& label);
    virtual std::vector<Certificate*> getCertificates(bool);
    /*
    If you want to store certificate without a private key call unsetKey() or otherwise
    the certificate will be placed in "Your Certificate" on Firefox. To store certificate with
    its private key, call setKeyId() before storing private key and certificate.
    */
    virtual TokenOpResult::Value putCertificate(const Certificate& cert);
    virtual bool removeCertificate(const Certificate& cert);
    /*
    Call setKeyId() before using this function, make sure that you unsetKey() before doing other task after calling putPrivateKey()
    */
    virtual TokenOpResult::Value putPrivateKey(const RsaKey& data, const std::string& labelStr);
    /*
    Retrieves card information in the token
    */
    virtual CardStatus::Value getCardStatus(TokenInfo token);
    /*
    Retrieves card's current session
    */
    virtual unsigned long int getCardSession();
    virtual RsaKey* getPrivateKey(const RsaPublicKey& publicKey);
    virtual bool removePrivateKey(const std::string& labelStr);
    virtual void* engine() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};
} // namespace Erpiko
#endif //  _P11_TOKEN_H_
