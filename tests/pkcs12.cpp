#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/pkcs12.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("Import pkcs12 from DER test") {
  GIVEN("A DER PKCS12") {
    DataSource* src = DataSource::fromFile("assets/p12.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Pkcs12* p12 = Pkcs12::fromDer(v, "solong");
      delete(src);
      THEN("There is nothing wrong") {
        REQUIRE_FALSE(p12 == nullptr);
        delete(p12);
        p12 = nullptr;
        REQUIRE(p12 == nullptr);
      }
    }
  }

  GIVEN("A DER PKCS12") {
    DataSource* src = DataSource::fromFile("assets/p12.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Pkcs12* p12 = Pkcs12::fromDer(v, "solong");
      delete(src);
      THEN("Can get private key and cert") {
        const RsaKey& key = p12->privateKey();
        REQUIRE(key.bits() == 2048);

        const Certificate& cert = p12->certificate();
        BigInt i(0x1003);
        REQUIRE(cert.serialNumber() == i);

        auto chain = p12->certificateChain();
        REQUIRE(chain.size() == 1);
        for (unsigned int i = 0; i < chain.size(); i ++) {
          const Certificate* c = chain.at(i);
          REQUIRE_FALSE(c == nullptr);
          const Identity& sid = c->subjectIdentity();
          REQUIRE(sid.get("commonName") == "sertifikat.id");
        }

      }
    }
  }

}

SCENARIO("Exporting pkcs12") {
  GIVEN("A DER PKCS12") {
    DataSource* src = DataSource::fromFile("assets/p12.der");
    REQUIRE_FALSE(src == nullptr);
    auto v = src->readAll();
    Pkcs12* p12 = Pkcs12::fromDer(v, "solong");
    THEN("Export it to DER") {
      auto der = p12->toDer();
      REQUIRE(der.size() > 0);
      THEN("Import again") {
        auto p12a = Pkcs12::fromDer(der, "solong");
        REQUIRE_FALSE(p12a == nullptr);
        const Certificate& c1 = p12->certificate();
        const Certificate& c2 = p12a->certificate();
        REQUIRE(c1.subjectIdentity() == c2.subjectIdentity());
      }
    }
  }

  GIVEN("p12, cert and key") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);
    REQUIRE_FALSE(key == nullptr);

    auto p12 = new Pkcs12("P12", "imapassword");
    REQUIRE_FALSE(p12 == nullptr);
    THEN("A cert and a key can be added") {
      p12->certificate(*cert);
      p12->privateKey(*key);
      auto der = p12->toDer();
      REQUIRE(der.size() > 0);
      THEN("DER can be imported back to P12") {
        Pkcs12* p12a = Pkcs12::fromDer(der, "imapassword");
        REQUIRE_FALSE(p12a == nullptr);
      }
    }
  }
}



} //namespace Erpiko
