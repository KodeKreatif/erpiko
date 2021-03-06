#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/utils.h"
#include "erpiko/bigint.h"
#include "erpiko/rsakey.h"
#include "erpiko/rsakey-public.h"
#include "erpiko/digest.h"

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

  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("Key is correctly initialized") {
      REQUIRE(pair->bits() == 1024);
      THEN("Gets the exposed public key ") {
        const RsaPublicKey& pub = pair->publicKey();
        auto pem = pub.toPem();
        auto pub2 = RsaPublicKey::fromPem(pem);
        THEN("The internal data must be the same") {
          const BigInt& exp1 = pub.exponent();
          const BigInt& exp2 = pub2->exponent();
          REQUIRE(exp1 == exp2);
          const BigInt& mod1 = pub.modulus();
          const BigInt& mod2 = pub2->modulus();
          REQUIRE(mod1 == mod2);
        }
      }
    }
  }
}

SCENARIO("Keys can encrypt and decrypt data") {
  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    THEN("can encrypt using public and decrypt using private key") {
      std::string s = "data";
      std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());

      auto result = pair->publicKey().encrypt(data);
      auto decrypted = pair->decrypt(result);
      REQUIRE(decrypted == data);
    }
  }

}

SCENARIO("Keys can sign and verify data") {
  GIVEN("A newly created key pair") {
    RsaKey* pair = RsaKey::create(1024);
    RsaKey* pair2 = RsaKey::create(1024);
    THEN("can sign using public and verify using private key") {
      ObjectId o(DigestConstants::SHA256);
      std::string s = "data";
      Digest *d = Digest::get(o);
      std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());
      std::vector<unsigned char> empty;
      d->update(data);
      auto hash = d->finalize(empty);

      auto result = pair->sign(hash, o);
      auto result2 = pair2->sign(hash, o);
      auto verified = pair->publicKey().verify(result, hash, o);
      auto verified2 = pair2->publicKey().verify(result, hash, o);
      auto verified3 = pair2->publicKey().verify(result2, hash, o);
      REQUIRE(verified == true);
      REQUIRE(verified2 == false);
      REQUIRE(verified3 == true);
    }
  }

}



} // namespace Erpiko
