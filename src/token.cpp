#include "erpiko/token.h"
#include "engine-p11.h"
#include <openssl/engine.h>

using namespace std;
namespace Erpiko {

class Token::Impl {
  public:

  EngineP11& engine;
  bool valid = false;

  Impl() : engine{ EngineP11::getInstance() } {
    engine.init();
  }

  bool load(string path) {
    valid = engine.load(path);
    return valid;
  }
};

Token::Token() : impl{ std::make_unique<Impl>()} {
}

Token::~Token() = default;

bool
Token::load(const std::string path) {
  return impl->load(path);
}

bool
Token::isValid() {
  return impl->valid;
}

} // namespace Erpiko
