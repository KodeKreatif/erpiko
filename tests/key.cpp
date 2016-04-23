#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "key.h"

namespace Erpiko {
SCENARIO("Keys can be created") {
  GIVEN("Empty keys") {
    RsaKey* key = new RsaKey();
    THEN("Key is not initialized") {
      REQUIRE(key->bits() == 0);
      THEN("Deleting key") {
        delete(key);
        key = nullptr;
        REQUIRE(key == nullptr);
      }
    }
  }

  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("Key is correctly initialized") {
      REQUIRE(pair->bits() == 1024);
    }
  }

}
} // namespace Erpiko
