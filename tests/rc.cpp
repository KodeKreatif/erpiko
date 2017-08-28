#include "catch.hpp"
#include <iostream>
#include "erpiko/oid.h"
#include "erpiko/cipher.h"
#include "erpiko/utils.h"
#include "cipher.h"

namespace Erpiko {

// Test vectors from RFC-2268
TestEncrypt("E-RC2-CBC-0", RC2_CBC, "88bca90e 90875a7f 0f79c384 627bafb2", "00000000 00000000", "2269552a b0f85ca6")
TestDecrypt("D-RC2-CBC-0", RC2_CBC, "88bca90e 90875a7f 0f79c384 627bafb2", "2269552a b0f85ca6", "00000000 00000000")

TestEncrypt("E-RC2-64-CBC-0", RC2_64_CBC, "ffffffff ffffffff", "ffffffff ffffffff", "278b27e4 2e2f0d49")
TestDecrypt("D-RC2-64-CBC-0", RC2_64_CBC, "ffffffff ffffffff", "278b27e4 2e2f0d49", "ffffffff ffffffff")

// Test vectors from OpenSSL
TestEncrypt("E-RC4-CBC-0", RC4_CBC, "0123456789abcdef0123456789abcdef", "0123456789abcdef", "75b7878099e0c596")
TestDecrypt("D-RC4-CBC-0", RC4_CBC, "0123456789abcdef0123456789abcdef", "75b7878099e0c596", "0123456789abcdef")
TestEncrypt("E-RC4-CBC-1", RC4_CBC, "0123456789abcdef0123456789abcdef", "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678", "66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf")
TestDecrypt("D-RC4-CBC-1", RC4_CBC, "0123456789abcdef0123456789abcdef", "66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf", "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678")

} // namespace Erpiko
