#include "erpiko/digest.h"
#include "erpiko/sha1.h"
#include "erpiko/sha224.h"
#include "erpiko/sha256.h"
#include "erpiko/sha384.h"
#include "erpiko/sha512.h"

namespace Erpiko {
Digest*
Digest::get(const ObjectId& algorithmId) {
  Digest *a = nullptr;
  if (algorithmId.toString() == "1.3.14.3.2.26") {
    return new Sha1;
  } else if (algorithmId.toString() == "2.16.840.1.101.3.4.2.4") {
    return new Sha224;
  } else if (algorithmId.toString() == "2.16.840.1.101.3.4.2.1") {
    return new Sha256;
  } else if (algorithmId.toString() == "2.16.840.1.101.3.4.2.2") {
    return new Sha384;
  } else if (algorithmId.toString() == "2.16.840.1.101.3.4.2.3") {
    return new Sha512;
  }

  return a;
}
} // namespace Erpiko
