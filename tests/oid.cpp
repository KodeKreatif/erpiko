#include "catch.hpp"

#include "erpiko/oid.h"

namespace Erpiko {

SCENARIO("Basic oid test") {
  GIVEN("A new oid") {
    ObjectId* oid = new ObjectId("2.5.4.3");
    THEN("It must be representable with a string") {
      REQUIRE(oid->humanize() == "commonName");
      REQUIRE(oid->toString() == "2.5.4.3");
    }
  }

  GIVEN("A new oid") {
    ObjectId* oid = new ObjectId("2.5.4.3");
    THEN("It must be freeable") {
      delete(oid);
      oid = nullptr;
      REQUIRE(oid == nullptr);
    }
  }

  GIVEN("A new oid") {
    ObjectId* oid = new ObjectId("2.5.4.3");
    REQUIRE(oid->humanize() == "commonName");
    THEN("It must be assignable from another oid") {
      ObjectId* oid2 = new ObjectId("2.5.4.7");
      *oid = *oid2;
      REQUIRE(oid->humanize() == "localityName");
    }
  }
}

SCENARIO("Basic oid comparison test") {
  GIVEN("A couple of oids") {
    ObjectId* oid1 = new ObjectId("2.5.4.3");
    ObjectId* oid2 = new ObjectId("2.5.4.3");
    THEN("Both oids must be the same") {
      REQUIRE(*oid1 == *oid2);
    }
  }
  GIVEN("A new oid") {
    ObjectId* oid = new ObjectId("2.5.4.3");
    THEN("It must be assignable from another oid") {
      ObjectId* oid2 = new ObjectId("2.5.4.7");
      *oid = *oid2;
      REQUIRE(*oid == *oid2);
    }
  }

}



} //namespace Erpiko
