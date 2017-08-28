#include "catch.hpp"
#include <iostream>
#include "erpiko/oid.h"
#include "erpiko/cipher.h"
#include "erpiko/utils.h"
#include "cipher.h"

namespace Erpiko {

// Test vectors from RFC-2144
TestEncrypt("E-DES-0", DES, "8000000000000000", "0000000000000000", "95A8D72813DAA94D")
TestDecrypt("D-DES-0", DES, "8000000000000000", "95A8D72813DAA94D", "0000000000000000")

} // namespace Erpiko
