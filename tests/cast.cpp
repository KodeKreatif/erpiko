#include "catch.hpp"
#include <iostream>
#include "erpiko/oid.h"
#include "erpiko/cipher.h"
#include "erpiko/utils.h"
#include "cipher.h"

namespace Erpiko {
// Test vectors from RFC-2144
TestEncrypt("E-CAST5-128-CBC-0", CAST5_128_CBC, "01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A", "01 23 45 67 89 AB CD EF", "23 8B 4F E5 84 7E 44 B2")
TestDecrypt("D-CAST5-128-CBC-0", CAST5_128_CBC, "01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A", "23 8B 4F E5 84 7E 44 B2", "01 23 45 67 89 AB CD EF")

} // namespace Erpiko
