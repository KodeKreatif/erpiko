#include "erpiko/cipher.h"
#include "cipher-openssl.h"

namespace Erpiko {

Cipher::Cipher() = default;
Cipher::~Cipher() = default;

Cipher::Cipher(CipherConstants::Mode mode, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
  (void) mode;
  (void) iv;
  (void) key;
}

Cipher*
Cipher::get(const ObjectId& algorithmId, CipherConstants::Mode mode, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
  (void) mode;
  (void) algorithmId;
  (void) iv;
  (void) key;

  Cipher *a = nullptr;

  a = new CipherOpenSsl(algorithmId.toString().c_str(),
      mode, key, iv);
  if (!((CipherOpenSsl*)a)->isValid()) {
    return nullptr;
  }

  return a;
}

void
Cipher::setTag(std::vector<unsigned char> tag) {
  (void) tag;
  // Empty
}

void
Cipher::setAad(std::vector<unsigned char> aad) {
  (void) aad;
  // Empty
}

std::vector<unsigned char>
Cipher::getTag() {
  std::vector<unsigned char> ret;
  return ret;
}

} // namespace Erpiko
