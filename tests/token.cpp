#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"
#include <iostream>

using namespace std;
namespace Erpiko {

SCENARIO("Token init", "[.][p11]") {
  GIVEN("A token") {
    THEN("Token is initialized") {
      int bits = 1024;
      RsaKey* k = RsaKey::create(bits);

      auto v = Utils::fromHexString("751965349686009581002736762779192355");
      auto enc = k->publicKey().encrypt(v);
      Token t;
      auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
      REQUIRE(r == true);
      r = t.login(933433059, "qwerty");
      REQUIRE(r == true);

      t.setKeyId(10, "erpik");
      k = RsaKey::create(1024);
      auto vec = k->toDer();
      REQUIRE(k->onDevice() == true);
      REQUIRE(vec.size() == 0);
      auto enc2 = k->publicKey().encrypt(v);
      auto enc3 = k->publicKey().encrypt(v);
      REQUIRE(enc2 != enc3);
      REQUIRE(enc2.size() == bits/8);

      auto dec3 = k->decrypt(enc2);
      REQUIRE(dec3 == v);

      REQUIRE(t.logout() == true);
      enc2 = k->publicKey().encrypt(v);
      REQUIRE(enc2.size() == 0);
    }
  }
}

} // namespace Erpiko
