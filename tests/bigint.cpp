#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/utils.h"
#include "erpiko/bigint.h"

namespace Erpiko {

SCENARIO("An empty BigInt can be created") {
  GIVEN("A new empty BigInt") {
    BigInt b;
    REQUIRE_FALSE(&b == nullptr);
  }

  GIVEN("A new empty BigInt pointer") {
    BigInt* b = new BigInt();
    REQUIRE_FALSE(b == nullptr);
    delete(b);
    b = nullptr;
    REQUIRE(b == nullptr);
  }
}


SCENARIO("BigInt can be created from integer type") {
  GIVEN("A new BigInt") {
  }
}
} // namespace Erpiko
