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
    BigInt b(1);
    THEN("It is not null") {
      REQUIRE_FALSE(&b == nullptr);
      THEN("And it is the same with another big int created with the same integer") {
        BigInt b1(1);
        REQUIRE(b == b1);
      }
    }
  }
}

SCENARIO("BigInt can be created from string") {
  GIVEN("A new BigInt") {
    BigInt* b = BigInt::fromString("120");
    THEN("It is not null") {
      REQUIRE_FALSE(&b == nullptr);
      THEN("And it is the same with another big int created with the same hexstring") {
        BigInt b1(120);
        REQUIRE(*b == b1);
      }
    }

  }

  GIVEN("A new BigInt") {
    BigInt* b = BigInt::fromString("0x120");
    THEN("It is not null") {
      REQUIRE_FALSE(&b == nullptr);
      THEN("And it is the same with another big int created with the same hexstring") {
        BigInt b1(0x120);
        REQUIRE(*b == b1);
      }
    }
  }

  GIVEN("A new BigInt incorrectly initialized") {
    BigInt* b = BigInt::fromString("0xhoho");
    THEN("It should be null") {
      REQUIRE(b == nullptr);
    }
    BigInt* b2 = BigInt::fromString("hoho");
    THEN("It should also be null") {
      REQUIRE(b2 == nullptr);
    }

  }

}


} // namespace Erpiko
