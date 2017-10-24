#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"

namespace Erpiko {

SCENARIO("Token init", "[.][p11]") {
  GIVEN("A token") {
    THEN("Token is initialized") {
      RsaKey* k = RsaKey::create(1024);

      auto v = Utils::fromHexString("12345678");
      auto enc = k->publicKey().encrypt(v);
      Token t;
      auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
      REQUIRE(r == true);

      //k = RsaKey::create(1024);
      auto enc2 = k->publicKey().encrypt(v);

    }
  }
}

} // namespace Erpiko
