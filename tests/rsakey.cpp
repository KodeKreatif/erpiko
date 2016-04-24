#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/utils.h"
#include "erpiko/rsakey.h"

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
      THEN("Key is exported as PEM without password") {
        auto pem = pair->toPem();

        THEN("Key is able to be reimported") {
          RsaKey* import = RsaKey::fromPem(pem);
          REQUIRE(pem == import->toPem());
        }
      }
    }
  }

  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("Key is correctly initialized") {
      REQUIRE(pair->bits() == 1024);
      THEN("Key is exported as PEM with password") {
        auto pem = pair->toPem("omama");
        THEN("Key is able to be reimported") {
          RsaKey* import = RsaKey::fromPem(pem, "omama");
          REQUIRE(import->bits() == 1024);
        }
        THEN("Key is not importable") {
          RsaKey* import = RsaKey::fromPem(pem, "wrong");
          REQUIRE(import == nullptr);
        }
      }
    }
  }

  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("Key is correctly initialized") {
      REQUIRE(pair->bits() == 1024);
      THEN("Key is exported as DER without password") {
        auto der = pair->toDer();
        THEN("Key is able to be reimported") {
          RsaKey* import = RsaKey::fromDer(der);
          REQUIRE(der == import->toDer());
          REQUIRE(import->bits() == 1024);
        }
      }
    }
  }

  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("Key is correctly initialized") {
      REQUIRE(pair->bits() == 1024);
      THEN("Key is exported as DER with password") {
        auto der = pair->toDer("omama");
        THEN("Key is able to be reimported") {
          RsaKey* import = RsaKey::fromDer(der, "omama");
          REQUIRE_FALSE(import == nullptr);
          REQUIRE(import->bits() == 1024);
        }

        THEN("Key is not importable with wrong password") {
          RsaKey* import = RsaKey::fromDer(der, "wrong");
          REQUIRE(import == nullptr);
        }
      }
    }
  }

}
} // namespace Erpiko
