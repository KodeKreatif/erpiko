#include "erpiko/p11-token.h"
#include "engine-p11.h"
#include <openssl/engine.h>

using namespace std;
namespace Erpiko {

class P11Token::Impl {
  public:

  EngineP11& engine;
  bool valid = false;

  Impl() : engine{ EngineP11::getInstance() } {
    engine.init();
  }

  ~Impl() {
    engine.finalize();
  }

  bool load(string path) {
    valid = engine.load(path);
    return valid;
  }

};

P11Token::P11Token() : impl{ std::make_unique<Impl>()} {
}

P11Token::~P11Token() = default;

bool
P11Token::load(const std::string path) {
  return impl->load(path);
}

bool
P11Token::isValid() {
  return impl->valid;
}

CardStatus::Value P11Token::waitForCardStatus(int &slot) const {
  bool result = impl->engine.waitForCardStatus(slot);
  if (result != true) {
    return CardStatus::NOT_PRESENT;
  }
  return CardStatus::PRESENT;
}

bool
P11Token::login(const unsigned long slot, const std::string& pin) const {
  return impl->engine.login(slot, pin);
}

bool
P11Token::logout() const {
  return impl->engine.logout();
}

void
P11Token::setKeyId(const unsigned int id, const std::string& label) {
  impl->engine.setKeyLabel(label);
  impl->engine.setKeyId(id);
}

TokenOpResult::Value
P11Token::putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data) {
  return impl->engine.putData(applicationName, label, data);
}

std::vector<unsigned char>
P11Token::getData(const std::string& applicationName, std::string& label) {
  return impl->engine.getData(applicationName, label);
}

std::vector<Certificate*>
P11Token::getCertificates() {
  return impl->engine.getCertificates();
}

TokenOpResult::Value
P11Token::putCertificate(const Certificate* cert) {
  return impl->engine.putCertificate(cert);
}

void *
P11Token::engine() const {
  return (void*) impl->engine.erpikoEngine;
}

} // namespace Erpiko
