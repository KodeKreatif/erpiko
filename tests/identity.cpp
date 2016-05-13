#include "catch.hpp"

#include "erpiko/identity.h"
#include "erpiko/utils.h"

namespace Erpiko {

SCENARIO("Basic identity test") {
  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    Identity* id2 = new Identity();
    id2->set("commonName", "abc");
    REQUIRE(*id == *id2);
  }
}

SCENARIO("Further identity test") {
  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    auto v = id->toDer();
    auto s = Utils::hexString(v);
    THEN("The der version is correctly created") {
      REQUIRE(s == "300e310c300a06035504030c03616263");
    }
  }

  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    auto abc = id->get("commonName");
    THEN("The property is properly set") {
      REQUIRE(abc == "abc");
    }
  }

  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    auto v = id->toDer();
    auto s = Utils::hexString(v);
    REQUIRE(s == "300e310c300a06035504030c03616263");
    THEN("The commonName is changed to another value") {
      id->set("commonName", "Omama");
      auto v2 = id->toDer();
      auto s2 = Utils::hexString(v2);
      THEN("The der version is correctly created") {
        REQUIRE_FALSE(s2 == "300e310c300a06035504030c03616263");
        REQUIRE(s2 == "3010310e300c06035504030c054f6d616d61");
      }
    }
  }

  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    auto v = id->toDer();
    auto s = Utils::hexString(v);
    REQUIRE(s == "300e310c300a06035504030c03616263");
    THEN("Create another Identity using the DER data") {
      Identity* id2 = Identity::fromDer(v);
      THEN("Both identities must match") {
        REQUIRE(*id == *id2);
      }
    }
  }



}

SCENARIO("Export test") {
  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    id->set("UID", "abc");
    THEN("One line DN is produced") {
      REQUIRE(id->toString() == "/CN=abc/UID=abc");
    }
  }

  GIVEN("A new Identity") {
    Identity* id = new Identity();
    id->set("commonName", "abc");
    id->set("UID", "abc");
    THEN("One line DN is produced") {
      REQUIRE(id->toString(",") == "CN=abc,UID=abc");
    }
  }

}



} //namespace Erpiko
