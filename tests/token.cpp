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
      t.setKeyId(10, "erpiko");
      auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
      REQUIRE(r == true);
      r = t.login(134972729, "qwerty");
      REQUIRE(r == true);

      k = RsaKey::create(1024);
      auto vec = k->toDer();
      REQUIRE(k->onDevice() == true);
      REQUIRE(vec.size() == 0);
      auto enc2 = k->publicKey().encrypt(v);

    }
  }
}

} // namespace Erpiko
