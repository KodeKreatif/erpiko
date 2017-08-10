#include "erpiko/rng.h"
#include <openssl/rand.h>

namespace Erpiko {

class Rng::Impl {
  public:
  std::function<void(void)> onEntropyFulfilled;
  Impl() {
  }

  void seed(const void* buffer, const unsigned int length) {
    RAND_seed(buffer, length);
    if (RAND_status() == 1 && onEntropyFulfilled) {
      onEntropyFulfilled();
    }
  }

  std::vector<unsigned char> random(const unsigned int length) {
    std::vector<unsigned char> ret(length);

    RAND_bytes(ret.data(), length);
    return ret;
  }

};

Rng::Rng() : impl{std::make_unique<Impl>()} {
}

Rng::~Rng() = default;

void
Rng::seed(const void* buffer, const unsigned int length) {
  impl->seed(buffer, length);
}

std::vector<unsigned char>
Rng::random(const unsigned int length) {
  return impl->random(length);
}

void
Rng::onEntropyFulfilled(std::function<void(void)> f) {
  impl->onEntropyFulfilled = f;
}

} // namespace Erpiko
